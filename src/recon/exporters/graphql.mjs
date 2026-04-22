export class GraphqlExporter {
  /**
   * @param {ReturnType<import('../endpoint-inventory.mjs').EndpointInventory['build']>} inventory
   */
  static convert(inventory) {
    const graphqlEndpoints = inventory.endpoints.filter(
      (e) => e.path.includes('graphql') || e.sampleUrls.some((u) => u.includes('graphql')),
    );

    return {
      detectedGraphQLEndpoints: graphqlEndpoints.map((e) => ({
        url: e.sampleUrls[0],
        method: e.method,
        hits: e.hits,
      })),
      suggestedNextStep: graphqlEndpoints.length
        ? 'Feed the endpoint URL into graphqlai with schema/introspection when authorized — see graphqlai docs.'
        : 'No GraphQL URL pattern observed in JSON traffic; try SPA network panel or graphqlai fingerprint flows.',
      restEndpoints: inventory.endpoints
        .filter((e) => !e.path.includes('graphql'))
        .map((e) => ({
          path: e.path,
          method: e.method,
          host: e.host,
          hits: e.hits,
        })),
    };
  }
}
