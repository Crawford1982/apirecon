export class OpenApiExporter {
  /**
   * @param {ReturnType<import('../endpoint-inventory.mjs').EndpointInventory['build']>} inventory
   */
  static convert(inventory) {
    const origin = inventory.origins[0] || 'https://example.com';
    const spec = {
      openapi: '3.0.3',
      info: {
        title: `apirecon generated spec — ${origin}`,
        version: '1.0.0',
        description:
          'Auto-generated from captured browser traffic. Review before relying on this for tooling.',
      },
      servers: inventory.origins.map((o) => ({ url: o })),
      paths: {},
    };

    /** @type {Record<string, Record<string, unknown>>} */
    const paths = {};

    for (const endpoint of inventory.endpoints) {
      const pathKey = endpoint.path;
      if (!paths[pathKey]) paths[pathKey] = {};

      const methodKey = endpoint.method.toLowerCase();
      const parameters = endpoint.queryParams.map((p) => ({
        name: p,
        in: 'query',
        required: false,
        schema: { type: 'string' },
      }));

      /** @type {Record<string, unknown>} */
      const op = {
        summary: `Observed ${endpoint.hits} time(s)`,
        parameters: parameters.length ? parameters : undefined,
        responses: {
          '200': {
            description: 'Observed JSON response',
            content: {
              'application/json': {
                schema: this.inferSchema(endpoint.responseShapes),
              },
            },
          },
        },
      };

      if (['post', 'put', 'patch'].includes(methodKey)) {
        op.requestBody = {
          content: {
            'application/json': {
              schema: { type: 'object', additionalProperties: true },
            },
          },
        };
      }

      paths[pathKey][methodKey] = op;
    }

    spec.paths = paths;
    return spec;
  }

  /** @param {string[][]} shapes */
  static inferSchema(shapes) {
    if (!shapes?.length) return { type: 'object', additionalProperties: true };
    const allKeys = new Set();
    for (const shape of shapes) {
      for (const key of shape) allKeys.add(key);
    }
    /** @type {Record<string, unknown>} */
    const properties = {};
    for (const key of allKeys) {
      properties[key] = { type: 'string' };
    }
    return { type: 'object', properties };
  }
}
