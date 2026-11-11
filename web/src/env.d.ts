// Declares the VITE_ variables the console reads. Everything here ends up in the public
// bundle, so only public values may be added (see src/config.ts and .env.example).
interface ImportMetaEnv {
  readonly VITE_API_BASE_URL?: string;
}
