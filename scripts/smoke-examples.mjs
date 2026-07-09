#!/usr/bin/env node

import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { setTimeout as delay } from "node:timers/promises";

const repoRoot = new URL("..", import.meta.url);
const host = "127.0.0.1";
const platformAuthorization = "Bearer demo-agent";
const serviceExamples = [
  {
    credentialMode: "jwt",
    name: "aep-service-express",
    script: "examples/aep-service-express/dist/index.js"
  },
  {
    credentialMode: "jwt",
    name: "aep-service-fastify",
    script: "examples/aep-service-fastify/dist/index.js"
  },
  {
    credentialMode: "jwt",
    name: "aep-service-hono",
    script: "examples/aep-service-hono/dist/index.js"
  },
  {
    credentialMode: "jwt",
    name: "aep-service-next",
    script: "examples/aep-service-next/dist/index.js"
  },
  {
    credentialMode: "jwt",
    name: "aep-service-credential-jwt",
    script: "examples/aep-service-credential-jwt/dist/index.js"
  },
  {
    credentialMode: "api-key",
    name: "aep-service-credential-api-key",
    script: "examples/aep-service-credential-api-key/dist/index.js"
  },
  {
    credentialMode: "basic",
    name: "aep-service-credential-basic",
    script: "examples/aep-service-credential-basic/dist/index.js"
  },
  {
    credentialMode: "oauth-bearer",
    name: "aep-service-credential-oauth",
    script: "examples/aep-service-credential-oauth/dist/index.js"
  }
];
const children = [];

try {
  await main();
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
} finally {
  await stopChildren();
}

async function main() {
  const platformPort = await unusedPort();
  const platformUrl = `http://${host}:${platformPort}`;
  const serviceDid = `did:web:${encodeURIComponent(`${host}:${platformPort}`)}:services:example-service`;
  const platform = startProcess(
    "aep-platform-ephemeral",
    "examples/aep-platform-ephemeral/dist/index.js",
    {
      PLATFORM_AUTHORIZATION: platformAuthorization,
      PORT: String(platformPort),
      PUBLIC_BASE_URL: platformUrl
    }
  );

  await waitForHttp(`${platformUrl}/health`, platform);

  for (const service of serviceExamples) {
    await smokeService({
      platformUrl,
      service,
      serviceDid
    });
  }
}

async function smokeService({ platformUrl, service, serviceDid }) {
  const servicePort = await unusedPort();
  const serviceUrl = `http://${host}:${servicePort}`;
  const serviceProcess = startProcess(service.name, service.script, {
    PORT: String(servicePort),
    SERVICE_DID: serviceDid
  });

  try {
    await waitForHttp(`${serviceUrl}/.well-known/aep`, serviceProcess);

    const agentResult = await runProcess(
      `${service.name} agent`,
      "examples/aep-agent-did-web-grant-status-revoke/dist/index.js",
      {
        PLATFORM_AUTHORIZATION: platformAuthorization,
        PLATFORM_URL: platformUrl,
        SERVICE_URL: serviceUrl
      }
    );
    const payload = parseJson(agentResult.stdout, `${service.name} agent output`);

    assertField(payload, "agentDid", "string", service.name);
    assertEqual(payload["credentialMode"], service.credentialMode, service.name, "credentialMode");
    assertEqual(payload["serviceDid"], serviceDid, service.name, "serviceDid");
    assertProtectedBody(payload["resource"], service.name, "resource");
    assertProtectedBody(payload["profile"], service.name, "profile");

    if (service.credentialMode === "jwt") {
      assertEqual(payload["grant"], null, service.name, "grant");
      assertEqual(payload["revoke"], null, service.name, "revoke");
    } else {
      assertRecord(payload["grant"], service.name, "grant");
      assertRecord(payload["revoke"], service.name, "revoke");
    }

    console.log(`smoke-examples: ${service.name} OK (${service.credentialMode})`);
  } finally {
    await stopChild(serviceProcess);
  }
}

function startProcess(name, script, env) {
  const child = spawn(process.execPath, [script], {
    cwd: repoRoot,
    env: {
      ...process.env,
      ...env
    },
    stdio: ["ignore", "pipe", "pipe"]
  });
  const state = {
    child,
    name,
    stderr: "",
    stdout: ""
  };

  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    state.stdout += chunk;
  });
  child.stderr.on("data", (chunk) => {
    state.stderr += chunk;
  });
  state.exit = new Promise((resolve) => {
    child.once("exit", (code, signal) => {
      state.code = code;
      state.signal = signal;
      resolve();
    });
  });
  children.push(state);

  return state;
}

async function runProcess(name, script, env) {
  const state = startProcess(name, script, env);

  await state.exit;
  removeChild(state);

  if (state.code !== 0) {
    throw new Error(formatProcessFailure(state));
  }

  return state;
}

async function stopChildren() {
  await Promise.all([...children].map(stopChild));
}

async function stopChild(state) {
  removeChild(state);

  if (state.code !== undefined || state.child.exitCode !== null) {
    await state.exit;
    return;
  }

  state.child.kill("SIGTERM");
  await Promise.race([
    state.exit,
    delay(2_000).then(() => {
      if (state.code === undefined && state.child.exitCode === null) {
        state.child.kill("SIGKILL");
      }
    })
  ]);
}

function removeChild(state) {
  const index = children.indexOf(state);

  if (index >= 0) {
    children.splice(index, 1);
  }
}

async function waitForHttp(url, state) {
  const deadline = Date.now() + 10_000;
  let lastError;

  while (Date.now() < deadline) {
    if (state.code !== undefined || state.child.exitCode !== null) {
      await state.exit;
      throw new Error(formatProcessFailure(state));
    }

    try {
      const response = await fetch(url);

      if (response.ok) {
        return;
      }

      lastError = new Error(`HTTP ${response.status}`);
    } catch (error) {
      lastError = error;
    }

    await delay(100);
  }

  throw new Error(
    `${state.name} did not become ready at ${url}: ${
      lastError instanceof Error ? lastError.message : String(lastError)
    }\n${formatLogs(state)}`
  );
}

async function unusedPort() {
  const server = createServer();

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, host, resolve);
  });

  const address = server.address();

  await new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) {
        reject(error);
        return;
      }

      resolve();
    });
  });

  if (typeof address !== "object" || address === null) {
    throw new Error("Expected TCP server address.");
  }

  return address.port;
}

function parseJson(value, label) {
  try {
    return JSON.parse(value);
  } catch (error) {
    throw new Error(
      `Could not parse ${label} as JSON: ${
        error instanceof Error ? error.message : String(error)
      }\n${value}`
    );
  }
}

function assertProtectedBody(value, serviceName, field) {
  assertRecord(value, serviceName, field);

  if (field === "resource") {
    assertEqual(value["resource"], "example-resource", serviceName, field);
    return;
  }

  assertEqual(value["updated"], true, serviceName, field);
}

function assertRecord(value, serviceName, field) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${serviceName}: expected ${field} to be an object.`);
  }
}

function assertField(value, field, type, serviceName) {
  assertRecord(value, serviceName, "agent output");

  if (typeof value[field] !== type) {
    throw new Error(`${serviceName}: expected ${field} to be ${type}.`);
  }
}

function assertEqual(actual, expected, serviceName, field) {
  if (actual !== expected) {
    throw new Error(
      `${serviceName}: expected ${field} to be ${JSON.stringify(expected)}, got ${JSON.stringify(
        actual
      )}.`
    );
  }
}

function formatProcessFailure(state) {
  return `${state.name} exited with code ${String(state.code)} signal ${String(
    state.signal
  )}\n${formatLogs(state)}`;
}

function formatLogs(state) {
  return ["--- stdout ---", state.stdout.trimEnd(), "--- stderr ---", state.stderr.trimEnd()].join(
    "\n"
  );
}
