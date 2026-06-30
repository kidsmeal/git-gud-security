-- True-positive fixtures for BaaS/RLS patterns

ALTER TABLE public.users DISABLE ROW LEVEL SECURITY;

CREATE POLICY "open_access" ON public.posts USING (true);
CREATE POLICY "open_write" ON public.posts WITH CHECK (true);

CREATE POLICY "metadata_bypass" ON public.profiles
  USING (auth.jwt() ->> 'user_metadata' ->> 'role' = 'admin');

ALTER TABLE public.messages REPLICA IDENTITY FULL;

CREATE OR REPLACE FUNCTION fetch_url(url text)
RETURNS void AS $$
BEGIN
  PERFORM net.http_get(url);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

ALTER ROLE authenticator SET search_path TO public, extensions;
