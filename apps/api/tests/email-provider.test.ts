import { beforeEach, describe, expect, it, vi } from "vitest";
import nodemailer from "nodemailer";
import { createSmtpEmailProvider, type EmailMessage } from "../src/modules/email/email-service.js";
import { createLogger } from "../src/infrastructure/logging/logger.js";

vi.mock("nodemailer", () => ({ default: { createTransport: vi.fn() } }));

const createTransportMock = vi.mocked(nodemailer.createTransport);
const logger = createLogger("silent");

function fakeTransport(sendMailImpl: () => Promise<{ accepted: string[]; rejected: string[]; messageId: string }>) {
  const sendMail = vi.fn().mockImplementation(sendMailImpl);
  createTransportMock.mockReturnValue({ sendMail } as unknown as nodemailer.Transporter);
  return sendMail;
}

describe("smtp email provider", () => {
  beforeEach(() => {
    createTransportMock.mockReset();
  });

  it("rejects URLs with a non-smtp scheme", () => {
    expect(() => createSmtpEmailProvider(logger, "http://smtp.example.com")).toThrow(/scheme must be "smtp:" or "smtps:"/);
  });

  it("accepts smtp and smtps URLs", () => {
    expect(() => createSmtpEmailProvider(logger, "smtp://user:pass@smtp.example.com:587")).not.toThrow();
    expect(() => createSmtpEmailProvider(logger, "smtps://user:pass@smtp.example.com:465")).not.toThrow();
  });

  it("sends text and html through the transport", async () => {
    const sendMail = fakeTransport(() => Promise.resolve({ accepted: ["to@example.com"], rejected: [], messageId: "m1" }));
    const provider = createSmtpEmailProvider(logger, "smtps://user:pass@smtp.example.com:465");
    const message: EmailMessage = {
      from: "no-reply@example.com",
      to: "to@example.com",
      subject: "Verify your email",
      body: "text body",
      html: "<html><body>html body</body></html>",
    };
    await provider.send(message);
    expect(sendMail).toHaveBeenCalledTimes(1);
    const args = sendMail.mock.calls[0]![0] as Record<string, unknown>;
    expect(args).toMatchObject({ to: "to@example.com", subject: "Verify your email", text: "text body", html: "<html><body>html body</body></html>" });
  });

  it("throws when the server rejects the recipient", async () => {
    fakeTransport(() => Promise.resolve({ accepted: [], rejected: ["to@example.com"], messageId: "" }));
    const provider = createSmtpEmailProvider(logger, "smtps://user:pass@smtp.example.com:465");
    const message: EmailMessage = { from: "no-reply@example.com", to: "to@example.com", subject: "S", body: "b" };
    await expect(provider.send(message)).rejects.toThrow(/rejected recipients/);
  });
});
