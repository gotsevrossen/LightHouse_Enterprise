// Declares the VITE_ variables the console reads. Everything here ends up in the public
// bundle, so only public values may be added (see src/config.ts and .env.example). A test
// (src/publicEnv.test.ts) fails if the source reads any other VITE_ variable.
interface ImportMetaEnv {
  readonly VITE_API_BASE_URL?: string;
  readonly VITE_SUPABASE_URL?: string;
  readonly VITE_SUPABASE_PUBLISHABLE_KEY?: string;
}
