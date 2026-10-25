import { isNitwEmail, isValidNitwRollNumber, isValidTransactionId, normalizeRollNumber, normalizeTransactionId } from "./registrationChecks";

test("normalizes roll numbers without dropping leading zeroes", () => {
  expect(normalizeRollNumber(" 00123ab ")).toBe("00123AB");
  expect(isValidNitwRollNumber("00123456")).toBe(true);
});

test("rejects empty, numeric and malformed roll numbers", () => {
  for (const value of [undefined, "", 123456, "a b", "<script>", "a".repeat(33)]) {
    expect(isValidNitwRollNumber(value)).toBe(false);
  }
});

test("NITW classification accepts its student subdomains", () => {
  expect(isNitwEmail("student@nitw.ac.in")).toBe(true);
  expect(isNitwEmail("  STUDENT@NITW.AC.IN  ")).toBe(true);
  expect(isNitwEmail("student@student.nitw.ac.in")).toBe(true);
  expect(isNitwEmail("outside@evilnitw.ac.in")).toBe(false);
  expect(isNitwEmail("outside@example.com")).toBe(false);
  expect(isNitwEmail("outside@nitw.ac.in.example.com")).toBe(false);
});

test("normalizes and validates transaction IDs", () => {
  expect(normalizeTransactionId("  sbin126123456789 ")).toBe("SBIN126123456789");
  expect(isValidTransactionId("412345678901")).toBe(true);
  expect(isValidTransactionId("SBIN126123456789")).toBe(true);
  expect(isValidTransactionId("short")).toBe(false);
  expect(isValidTransactionId("bad space")).toBe(false);
});
});
