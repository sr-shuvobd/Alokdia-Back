import { randomUUID } from "node:crypto";

export function createRegistrationHandler({
  readSessionBody,
  validUsername,
  validPassword,
  createPasswordHash,
  send,
}) {
  return async function handleRegistration({ request, response, origin, users }) {
    const body = await readSessionBody(request);
    const username = typeof body.username === "string" ? body.username.trim() : "";
    if (!validUsername(username) || !validPassword(body.password)) {
      send(
        response,
        400,
        {
          error:
            "Username must be 3-32 letters/numbers/._- and password must be at least 8 characters.",
        },
        origin,
      );
      return;
    }

    const usernameNormalized = username.toLowerCase();
    if (await users.findOne({ usernameNormalized })) {
      send(response, 409, { error: "That username is already in use." }, origin);
      return;
    }

    try {
      const { salt, passwordHash } = await createPasswordHash(body.password);
      await users.insertOne({
        _id: randomUUID(),
        username,
        usernameNormalized,
        passwordSalt: salt,
        passwordHash,
        role: "admin",
        status: "pending",
        createdAt: new Date(),
      });
    } catch (error) {
      if (error?.code === 11000) {
        send(response, 409, { error: "That username is already in use." }, origin);
        return;
      }
      throw error;
    }

    send(
      response,
      201,
      { message: "Registration received. Wait for Super Admin approval." },
      origin,
    );
  };
}
