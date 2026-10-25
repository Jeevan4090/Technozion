/* eslint testing-library/no-unnecessary-act: "off" -- These tests use React DOM directly, which requires act. */
import React, { act } from "react";
import { createRoot } from "react-dom/client";
import AuthProvider, { useAuth } from "./AuthManager";

const mockNavigate = jest.fn();
const mockNotify = jest.fn();
jest.mock("react-router-dom", () => ({ useNavigate: () => mockNavigate }));
jest.mock("./SnackbarProvider", () => ({ useSnackbar: () => ({ notify: mockNotify }) }));
jest.mock("../components/Loader", () => ({ Loader: () => null }));

let container;
let root;
const originalFetch = global.fetch;
beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  localStorage.clear();
  global.fetch = jest.fn();
  mockNavigate.mockClear();
  mockNotify.mockClear();
  container = document.createElement("div");
  document.body.appendChild(container);
  root = createRoot(container);
});
afterEach(() => {
  act(() => root.unmount());
  container.remove();
  global.fetch = originalFetch;
  delete global.IS_REACT_ACT_ENVIRONMENT;
});

const mountSubmit = async (data) => {
  const Submit = () => {
    const { register } = useAuth();
    return <button onClick={() => register(data)}>Submit</button>;
  };
  await act(async () => root.render(<AuthProvider><Submit /></AuthProvider>));
  await act(async () => container.querySelector("button").click());
};

test("registration forwards NITW roll and all member identities and shows server-issued IDs", async () => {
  const teamMembers = [
    { name: "NITW Member", studentType: "nitw", rollNumber: "00123457" },
    { name: "External Member", studentType: "external" },
  ];
  const participants = [
    { name: "Lead", participantId: "00123456", rollNumber: "00123456", studentType: "nitw" },
    { name: "External Member", participantId: "26TZA7K2", studentType: "external", rollNumber: null },
  ];
  global.fetch
    .mockResolvedValueOnce(signOk)
    .mockResolvedValueOnce({ ok: true, json: async () => ({ secure_url: "https://example.com/test-id.png" }) })
    .mockResolvedValueOnce({ ok: true, json: async () => ({ email: "test@nitw.ac.in", participants }) });
  await mountSubmit({
    name: "Lead", email: "test@nitw.ac.in", rollNumber: " 00123456 ", password: "test-password",
    registrationType: "team", teamMembers, idDocument: new File(["test fixture"], "id.png", { type: "image/png" }),
  });
  const payload = JSON.parse(global.fetch.mock.calls[2][1].body);
  expect(payload.rollNumber).toBe("00123456");
  expect(payload.teamMembers).toEqual(teamMembers);
  expect(payload.participantId).toBeUndefined();
  expect(mockNavigate).toHaveBeenCalledWith("/registration-complete", { state: { participants } });
});

test("missing NITW roll is rejected before uploads or registration requests", async () => {
  await mountSubmit({ email: "test@nitw.ac.in" });
  expect(global.fetch).not.toHaveBeenCalled();
  expect(mockNotify).toHaveBeenCalledWith("Please enter your NITW roll number.", { variant: "error" });
});

const signOk = { ok: true, json: async () => ({ signature: "sig", apiKey: "key", cloudName: "cloud", params: { public_id: "tz/x/id-1", timestamp: 1, type: "authenticated", allowed_formats: "jpg,png,webp,pdf" } }) };

const nitwRegistration = () => ({
  name: "Lead", email: "test@nitw.ac.in", rollNumber: "00123456", password: "test-password",
  registrationType: "team", teamMembers: [{ name: "Member", studentType: "external" }],
  idDocument: new File(["test fixture"], "id.png", { type: "image/png" }),
});

test("upload connection failures identify the document rather than the registration service", async () => {
  const log = jest.spyOn(console, "log").mockImplementation(() => {});
  try {
    global.fetch.mockRejectedValueOnce(new TypeError("Failed to fetch"));
    await mountSubmit(nitwRegistration());
    expect(mockNotify).toHaveBeenLastCalledWith("Could not upload your id document. Check your connection and try again.", { variant: "error" });
    expect(global.fetch).toHaveBeenCalledTimes(1);
    expect(mockNavigate).not.toHaveBeenCalled();
  } finally { log.mockRestore(); }
});

test.each([500, 200])("non-JSON registration response (%i) shows a specific error without claiming success", async status => {
  global.fetch
    .mockResolvedValueOnce(signOk)
    .mockResolvedValueOnce({ ok: true, json: async () => ({ secure_url: "https://example.com/id.png" }) })
    .mockResolvedValueOnce({ ok: status === 200, status, json: async () => { throw new SyntaxError("Unexpected token <"); } });
  await mountSubmit(nitwRegistration());
  expect(mockNotify.mock.calls.at(-1)[0]).toContain(status === 200 ? "Check whether your account was created" : "invalid response (500)");
  expect(mockNavigate).not.toHaveBeenCalled();
});

test("registration connection errors are distinguished from successful document uploads", async () => {
  const log = jest.spyOn(console, "log").mockImplementation(() => {});
  try {
    global.fetch
      .mockResolvedValueOnce(signOk)
      .mockResolvedValueOnce({ ok: true, json: async () => ({ secure_url: "https://example.com/id.png" }) })
      .mockRejectedValueOnce(new TypeError("Failed to fetch"));
    await mountSubmit(nitwRegistration());
    expect(mockNotify).toHaveBeenLastCalledWith("Could not reach the registration service. Check that the backend is running and try again.", { variant: "error" });
    expect(mockNavigate).not.toHaveBeenCalled();
  } finally { log.mockRestore(); }
});

test.each([
  ["a script/executable", new File(["x"], "evil.html", { type: "text/html" })],
  ["an oversized file", new File([new Uint8Array(5 * 1024 * 1024 + 1)], "big.png", { type: "image/png" })],
])("%s is rejected in the browser before any network request", async (_name, file) => {
  const log = jest.spyOn(console, "log").mockImplementation(() => {});
  try {
    await mountSubmit({ ...nitwRegistration(), idDocument: file });
    expect(global.fetch).not.toHaveBeenCalled();
    expect(mockNavigate).not.toHaveBeenCalled();
  } finally { log.mockRestore(); }
});

test("uploads go to Cloudinary only with the backend-signed parameters, never an upload preset", async () => {
  global.fetch
    .mockResolvedValueOnce(signOk)
    .mockResolvedValueOnce({ ok: true, json: async () => ({ secure_url: "https://example.com/id.png" }) })
    .mockResolvedValueOnce({ ok: true, json: async () => ({ participants: [] }) });
  await mountSubmit({ ...nitwRegistration(), registrationToken: "reg-token" });
  expect(global.fetch.mock.calls[0][0]).toMatch(/\/api\/uploads\/sign$/);
  expect(JSON.parse(global.fetch.mock.calls[0][1].body)).toEqual({ kind: "id", registrationToken: "reg-token" });
  const [cloudUrl, cloudInit] = global.fetch.mock.calls[1];
  expect(cloudUrl).toBe("https://api.cloudinary.com/v1_1/cloud/image/upload");
  expect(cloudInit.body.get("signature")).toBe("sig");
  expect(cloudInit.body.get("public_id")).toBe("tz/x/id-1");
  expect(cloudInit.body.get("upload_preset")).toBeNull();
});
