import { afterEach, describe, expect, it, vi } from "vitest";
import { chatViaChatGPT, responsesInput } from "../inference/chatgpt-responses.js";
import { createInferenceClient } from "../conway/inference.js";

vi.mock("../inference/chatgpt-auth.js", () => ({ getChatGPTAccessToken: async () => "oauth-token" }));

afterEach(() => vi.unstubAllGlobals());

describe("ChatGPT Responses adapter", () => {
  it("translates system messages and tool history", () => {
    expect(responsesInput([
      { role: "system", content: "Rules" },
      { role: "assistant", content: "", tool_calls: [{ id: "call1", type: "function", function: { name: "exec", arguments: "{}" } }] },
      { role: "tool", content: "done", tool_call_id: "call1" },
    ])).toEqual([
      { role: "developer", content: "Rules" },
      { type: "function_call", call_id: "call1", name: "exec", namespace: "automaton", arguments: "{}" },
      { type: "function_call_output", call_id: "call1", output: "done" },
    ]);
  });

  it("translates a completed stream and sends supported request fields", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response('data: {"type":"response.completed","response":{"id":"r1","model":"m","output":[{"type":"message","content":[{"type":"output_text","text":"hello"}]},{"type":"function_call","call_id":"c1","name":"exec","arguments":"{}"}],"usage":{"input_tokens":2,"output_tokens":3,"total_tokens":5}}}\n\n'));
    vi.stubGlobal("fetch", fetchMock);
    const result = await chatViaChatGPT("secret", "m", [{ role: "user", content: "hi" }], [{ type: "function", function: { name: "exec", description: "Execute", parameters: { type: "object" } } }]);
    expect(result.message.content).toBe("hello");
    expect(result.toolCalls?.[0].function.name).toBe("exec");
    expect(result.usage.totalTokens).toBe(5);
    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body).toMatchObject({ model: "m", stream: true, store: false, tools: [{ type: "namespace", name: "automaton" }] });
    expect(body).not.toHaveProperty("temperature");
  });

  it("rejects interrupted streams", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response('data: {"type":"response.created"}\n\n')));
    await expect(chatViaChatGPT("secret", "m", [])).rejects.toThrow("without completion");
  });

  it("routes calls to the chosen ChatGPT model instead of the router's model", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response('data: {"type":"response.completed","response":{"id":"r1","output":[]}}\n\n'));
    vi.stubGlobal("fetch", fetchMock);
    const client = createInferenceClient({ apiUrl: "https://conway.example", apiKey: "conway-key", defaultModel: "conway-model", maxTokens: 100, chatgptModel: "chatgpt-model" });
    await client.chat([{ role: "user", content: "hi" }], { model: "other-model" });
    expect(fetchMock.mock.calls[0][0]).toBe("https://api.openai.com/v1/responses");
    expect(fetchMock.mock.calls[0][1].headers.Authorization).toBe("Bearer oauth-token");
    expect(JSON.parse(fetchMock.mock.calls[0][1].body).model).toBe("chatgpt-model");
  });
});
