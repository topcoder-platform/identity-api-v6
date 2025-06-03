// Declare the module so TypeScript knows it exists, even without explicit types.
declare module 'topcoder-bus-api-wrapper' {
  // Define the shape of the function exported by the module.
  // You might need to adjust 'any' based on the actual expected input/output.
  function busApi(options: any): any;
  export = busApi;
}
