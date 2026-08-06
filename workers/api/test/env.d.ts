declare module "cloudflare:test" {
  // The tests receive the worker's own bindings (singleWorker mode).
  interface ProvidedEnv extends Env {}
}
