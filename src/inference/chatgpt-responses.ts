import type { ChatMessage, InferenceResponse, InferenceToolDefinition, InferenceToolCall } from "../types.js";

/** Translate the runtime's chat history into stateless Responses API input. */
export function responsesInput(messages: ChatMessage[]): Record<string, unknown>[] {
  const input: Record<string, unknown>[] = [];
  for (const message of messages) {
    if (message.role === "tool") {
      input.push({ type: "function_call_output", call_id: message.tool_call_id, output: message.content });
      continue;
    }
    if (message.responsesOutput?.length) {
      input.push(...message.responsesOutput);
      continue;
    }
    if (message.content) {
      input.push({ role: message.role === "system" ? "developer" : message.role, content: message.content });
    }
    for (const call of message.tool_calls ?? []) {
      input.push({ type: "function_call", call_id: call.id, name: call.function.name, namespace: "automaton", arguments: call.function.arguments });
    }
  }
  return input;
}

/** ChatGPT plan requests must be streamed and must carry the complete history. */
export async function chatViaChatGPT(
  token: string,
  model: string,
  messages: ChatMessage[],
  tools: InferenceToolDefinition[] = [],
): Promise<InferenceResponse> {
  const body: Record<string, unknown> = { model, input: responsesInput(messages), stream: true, store: false };
  if (tools.length) {
    body.tools = [{ type: "namespace", name: "automaton", description: "Tools available to the automaton", tools: tools.map(({ function: fn }) => ({ type: "function", ...fn, strict: false })) }];
  }
  const response = await fetch("https://api.openai.com/v1/responses", {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(120_000),
  });
  if (!response.ok) throw new Error(`ChatGPT inference failed (${response.status}): ${await response.text()}`);
  if (!response.body) throw new Error("ChatGPT inference returned no stream");
  let buffer = "";
  let completed: any;
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  const processEvent = (event: string) => {
    const data = event.split(/\r?\n/).filter(line => line.startsWith("data:")).map(line => line.slice(5).trimStart()).join("\n");
    if (!data || data === "[DONE]") return;
    const parsed = JSON.parse(data);
    if (parsed.type === "response.failed" || parsed.type === "response.incomplete" || parsed.type === "error") {
      throw new Error(`ChatGPT inference ${parsed.type}: ${JSON.stringify(parsed.response?.error ?? parsed.error ?? parsed.response?.incomplete_details ?? {})}`);
    }
    if (parsed.type === "response.completed") completed = parsed.response;
  };
  while (true) {
    const { value, done } = await reader.read();
    buffer += decoder.decode(value, { stream: !done });
    const events = buffer.split(/\r?\n\r?\n/);
    buffer = events.pop() ?? "";
    for (const event of events) processEvent(event);
    if (done) break;
  }
  if (buffer.trim()) processEvent(buffer);
  if (!completed) throw new Error("ChatGPT inference stream ended without completion");
  const calls: InferenceToolCall[] = [];
  let content = "";
  for (const item of completed.output ?? []) {
    if (item.type === "message") {
      for (const part of item.content ?? []) if (part.type === "output_text") content += part.text;
    } else if (item.type === "function_call") {
      calls.push({ id: item.call_id, type: "function", function: { name: item.name, arguments: item.arguments } });
    }
  }
  const promptTokens = completed.usage?.input_tokens ?? 0;
  const completionTokens = completed.usage?.output_tokens ?? 0;
  return {
    id: completed.id, model: completed.model ?? model,
    message: { role: "assistant", content, ...(calls.length ? { tool_calls: calls } : {}) },
    toolCalls: calls.length ? calls : undefined,
    usage: { promptTokens, completionTokens, totalTokens: completed.usage?.total_tokens ?? promptTokens + completionTokens },
    finishReason: calls.length ? "tool_calls" : "stop",
    responsesOutput: calls.length ? completed.output : undefined,
  };
}

/** Verify both a tool call and the stateless follow-up without executing external actions. */
export async function verifyChatGPTProvider(token: string, model: string): Promise<void> {
  const tools: InferenceToolDefinition[] = [{ type: "function", function: { name: "connection_check", description: "Verify the provider connection", parameters: { type: "object", properties: {}, additionalProperties: false } } }];
  const initial: ChatMessage = { role: "user", content: "Call the connection_check tool, then confirm it succeeded." };
  const first = await chatViaChatGPT(token, model, [initial], tools);
  const call = first.toolCalls?.find(item => item.function.name === "connection_check");
  if (!call || first.toolCalls?.length !== 1) throw new Error("ChatGPT provider check did not return the expected tool call");
  const followup = await chatViaChatGPT(token, model, [initial, { ...first.message, responsesOutput: first.responsesOutput }, { role: "tool", tool_call_id: call.id, content: "Connection check succeeded." }], tools);
  if (!followup.message.content && !followup.toolCalls?.length) throw new Error("ChatGPT provider check returned an empty follow-up");
}
