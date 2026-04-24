import test from 'node:test';
import assert from 'node:assert';

import {
  extractGraphqlOperations,
  operationsToFindings,
  substituteVariable,
} from '../src/recon/graphql-parser.mjs';

function gqlRequest(url, body, method = 'POST') {
  return {
    type: 'request',
    url,
    method,
    postData: typeof body === 'string' ? body : JSON.stringify(body),
    status: 200,
    responseHeaders: { 'content-type': 'application/json' },
  };
}

test('extractGraphqlOperations parses POST /graphql body with variables', () => {
  const traffic = [
    gqlRequest('https://you.23andme.com/graphql', {
      operationName: 'GetProfile',
      query: 'query GetProfile($profileId: ID!) { profile(id: $profileId) { id name } }',
      variables: { profileId: 'c03abce18b5d5ddb' },
    }),
  ];
  const { operations, endpoints } = extractGraphqlOperations(traffic);
  assert.strictEqual(operations.length, 1);
  const op = operations[0];
  assert.strictEqual(op.operationName, 'GetProfile');
  assert.strictEqual(op.operationType, 'query');
  assert.strictEqual(op.idVariables.length, 1);
  assert.strictEqual(op.idVariables[0].name, 'profileId');
  assert.strictEqual(op.idVariables[0].value, 'c03abce18b5d5ddb');
  assert.strictEqual(op.idVariables[0].idType, 'hex-16');
  assert.ok(endpoints.includes('https://you.23andme.com/graphql'));
});

test('extractGraphqlOperations deduplicates by (endpoint, operationName) and counts hits', () => {
  const traffic = [
    gqlRequest('https://x.example.com/graphql', {
      operationName: 'Get',
      query: 'query Get($id: ID!) { thing(id: $id) { id } }',
      variables: { id: '1' },
    }),
    gqlRequest('https://x.example.com/graphql', {
      operationName: 'Get',
      query: 'query Get($id: ID!) { thing(id: $id) { id } }',
      variables: { id: '2' },
    }),
    gqlRequest('https://x.example.com/graphql', {
      operationName: 'Other',
      query: 'query Other { foo }',
      variables: {},
    }),
  ];
  const { operations } = extractGraphqlOperations(traffic);
  assert.strictEqual(operations.length, 2);
  const get = operations.find((o) => o.operationName === 'Get');
  assert.strictEqual(get.hits, 2);
});

test('extractGraphqlOperations ignores pagination-shaped variables', () => {
  const traffic = [
    gqlRequest('https://x.example.com/graphql', {
      operationName: 'List',
      query: 'query List($page: Int!, $size: Int!) { list(page:$page,size:$size) { id } }',
      variables: { page: 1, size: 20 },
    }),
  ];
  const { operations } = extractGraphqlOperations(traffic);
  assert.strictEqual(operations[0].idVariables.length, 0);
});

test('operationsToFindings emits one IDOR finding per id-shaped variable', () => {
  const traffic = [
    gqlRequest('https://x.example.com/graphql', {
      operationName: 'UpdateAddress',
      query: 'mutation UpdateAddress($profileId: ID!, $addressId: ID!, $city: String!) { ok }',
      variables: { profileId: 'c03abce18b5d5ddb', addressId: 'abcdefabcdefabcd', city: 'Palo Alto' },
    }),
  ];
  const { operations } = extractGraphqlOperations(traffic);
  const findings = operationsToFindings(operations);
  assert.strictEqual(findings.length, 2);
  for (const f of findings) {
    assert.strictEqual(f.idorSource, 'graphql-variable');
    assert.ok(f.operation?.endpointUrl);
    assert.ok(f.idorRisk >= 4);
  }
  // Mutations get a +2 risk bump vs. queries.
  assert.ok(findings[0].idorRisk >= 6);
});

test('substituteVariable mutates a nested variable value without touching others', () => {
  const op = {
    query: 'mutation Foo($input: Input!) { foo(input: $input) { ok } }',
    operationName: 'Foo',
    variables: { input: { profileId: 'old', meta: { note: 'keep' } } },
  };
  const mutated = substituteVariable(op, 'input.profileId', 'new');
  assert.strictEqual(mutated.variables.input.profileId, 'new');
  assert.strictEqual(mutated.variables.input.meta.note, 'keep');
  // original untouched
  assert.strictEqual(op.variables.input.profileId, 'old');
});
