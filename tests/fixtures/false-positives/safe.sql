-- False-positive fixtures: none of these should fire

-- RLS enabled (correct)
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;

-- proper scoped policy
CREATE POLICY "owner_only" ON public.posts
  USING (auth.uid() = owner_id);

-- proper write policy
CREATE POLICY "owner_insert" ON public.posts
  WITH CHECK (auth.uid() = owner_id);
