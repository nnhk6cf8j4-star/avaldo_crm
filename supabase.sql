-- avaldo.crm — Supabase bazasi
-- Supabase → SQL Editor → shu matnni to'liq qo'ying → Run.
-- Qayta ishga tushirilsa ham zarari yo'q: bor narsalar o'chmaydi.

-- 1. Kim kim: egasi va ishchilar (login = ism, parol bilan kiradi)
create table if not exists public.members (
  user_id    uuid primary key references auth.users (id) on delete cascade,
  login      text not null unique,
  name       text not null default '',
  role       text not null default 'worker' check (role in ('owner', 'worker', 'off')),
  worker_id  text,
  created_at timestamptz not null default now()
);

-- 2. Barcha yozuvlar: mijozlar, buyurtmalar, kassa, ombor, hamkorlik, sozlamalar
create table if not exists public.records (
  kind       text not null,
  id         text not null,
  data       jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now(),
  updated_by uuid,
  primary key (kind, id)
);

-- 3. Yordamchi funksiyalar
create or replace function public.my_role() returns text
language sql stable security definer set search_path = public
as $$ select role from public.members where user_id = auth.uid() $$;

create or replace function public.has_owner() returns boolean
language sql stable security definer set search_path = public
as $$ select exists (select 1 from public.members where role = 'owner') $$;

-- birinchi kirgan odam egasi bo'ladi; egasi bor bo'lsa, hech narsa o'zgarmaydi
create or replace function public.claim_owner(p_login text, p_name text) returns text
language plpgsql security definer set search_path = public
as $$
begin
  if auth.uid() is null then raise exception 'not signed in'; end if;
  lock table public.members in exclusive mode;
  if exists (select 1 from public.members where role = 'owner') then
    return coalesce((select role from public.members where user_id = auth.uid()), 'none');
  end if;
  insert into public.members (user_id, login, name, role)
  values (auth.uid(), lower(p_login), p_name, 'owner')
  on conflict (user_id) do update set role = 'owner', login = excluded.login, name = excluded.name;
  return 'owner';
end $$;

-- egasi ishchining parolini yangilaydi
create or replace function public.set_member_password(p_user uuid, p_password text) returns void
language plpgsql security definer set search_path = public, extensions
as $$
begin
  if coalesce(public.my_role(), '') <> 'owner' then raise exception 'only the owner can do this'; end if;
  if length(coalesce(p_password, '')) < 6 then raise exception 'password too short'; end if;
  if not exists (select 1 from public.members where user_id = p_user) then raise exception 'unknown member'; end if;
  update auth.users set encrypted_password = extensions.crypt(p_password, extensions.gen_salt('bf')), updated_at = now()
  where id = p_user;
end $$;

-- egasi avval ochilgan (lekin ro'yxatdan chiqib qolgan) loginni qayta ishchi qiladi
create or replace function public.adopt_login(p_email text, p_login text, p_name text, p_password text, p_worker text) returns uuid
language plpgsql security definer set search_path = public, extensions
as $$
declare uid uuid;
begin
  if coalesce(public.my_role(), '') <> 'owner' then raise exception 'only the owner can do this'; end if;
  if length(coalesce(p_password, '')) < 6 then raise exception 'password too short'; end if;
  select id into uid from auth.users where lower(email) = lower(p_email);
  if uid is null then raise exception 'unknown login'; end if;
  if exists (select 1 from public.members where user_id = uid and role = 'owner') then raise exception 'cannot change the owner'; end if;
  insert into public.members (user_id, login, name, role, worker_id)
  values (uid, lower(p_login), p_name, 'worker', nullif(p_worker, ''))
  on conflict (user_id) do update set role = 'worker', name = excluded.name, worker_id = excluded.worker_id;
  update auth.users set encrypted_password = extensions.crypt(p_password, extensions.gen_salt('bf')), updated_at = now()
  where id = uid;
  return uid;
end $$;

create or replace function public.records_touch() returns trigger
language plpgsql as $$
begin
  new.updated_at = now();
  new.updated_by = auth.uid();
  return new;
end $$;
drop trigger if exists records_touch on public.records;
create trigger records_touch before insert or update on public.records
for each row execute function public.records_touch();

-- 4. Kim nimani ko'radi va o'zgartiradi
--    Egasi: hammasini. Ishchi: mijozlar, buyurtmalar, ishchilar, hamkorlik ishlari va ish beruvchilar,
--    sozlamalarni ko'radi; faqat buyurtma va hamkorlik ishlarida bajarilgan ishni belgilaydi.
--    Kassa, ish haqi, ombor, ta'minot — faqat egasiga.
alter table public.records enable row level security;
alter table public.members enable row level security;

drop policy if exists records_read on public.records;
create policy records_read on public.records for select to authenticated using (
  public.my_role() = 'owner'
  or (public.my_role() = 'worker' and kind in ('clients', 'orders', 'workers', 'jobs', 'partners', 'meta'))
);
drop policy if exists records_add on public.records;
create policy records_add on public.records for insert to authenticated with check (
  public.my_role() = 'owner'
  or (public.my_role() = 'worker' and kind in ('orders', 'jobs'))
);
drop policy if exists records_change on public.records;
create policy records_change on public.records for update to authenticated using (
  public.my_role() = 'owner'
  or (public.my_role() = 'worker' and kind in ('orders', 'jobs'))
) with check (
  public.my_role() = 'owner'
  or (public.my_role() = 'worker' and kind in ('orders', 'jobs'))
);
drop policy if exists records_remove on public.records;
create policy records_remove on public.records for delete to authenticated using (public.my_role() = 'owner');

drop policy if exists members_read on public.members;
create policy members_read on public.members for select to authenticated using (
  public.my_role() is not null
);
drop policy if exists members_owner on public.members;
create policy members_owner on public.members for all to authenticated
using (public.my_role() = 'owner') with check (public.my_role() = 'owner');

revoke all on public.records, public.members from anon;
grant select, insert, update, delete on public.records, public.members to authenticated;
revoke execute on function public.claim_owner(text, text) from anon;
revoke execute on function public.set_member_password(uuid, text) from anon;
revoke execute on function public.adopt_login(text, text, text, text, text) from anon;
grant execute on function public.has_owner() to anon, authenticated;

-- 5. Bir telefonda kiritilgani boshqasida darhol ko'rinsin
do $$
begin
  alter publication supabase_realtime add table public.records;
exception when duplicate_object then null;
end $$;
