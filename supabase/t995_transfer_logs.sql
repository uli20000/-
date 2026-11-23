-- 2026-11-23 實際套用情形（Claude 經 Supabase 連接器）：
--   已套用：建表、RLS、t995_transfer_pw_ok/check/list/add、軟刪除版 t995_transfer_delete（設 deleted_at，list 不顯示）。
--   沒套用：下面的 revoke（RLS 已開且無 policy，網頁本來就讀不到表）、原本的硬刪除版 delete。
--   待美花在 SQL Editor 自己跑：最底下的 7 天清除排程（含 delete，連接器需要的確認視窗在 App 裡不會跳出）。
--   實際套用的函式以資料庫為準；軟刪除版見檔案最後。

-- 調撥工時查詢 v2：當日調撥紀錄（995 Supabase）
-- 2026-11-23 建立。紀錄只留 7 天（含今天），每天 00:05（台北）自動清除。
-- 網頁只能透過下面的函式讀寫；新增、刪除要值班密碼（只存雜湊）。

create table if not exists public.t995_transfer_logs (
  id uuid primary key default gen_random_uuid(),
  log_date date not null default (now() at time zone 'Asia/Taipei')::date,
  created_at timestamptz not null default now(),
  from_code text not null,
  from_name text not null,
  to_code text not null,
  to_name text not null,
  out_km numeric(6,1) not null,
  back_km numeric(6,1) not null,
  minutes integer,            -- null = 超過 17 km，請致電中心
  constraint t995_transfer_logs_code_chk check (from_code ~ '^TW[A-Z][0-9]{3}$' and to_code ~ '^TW[A-Z][0-9]{3}$' and from_code <> to_code),
  constraint t995_transfer_logs_name_chk check (length(from_name) between 1 and 40 and length(to_name) between 1 and 40),
  constraint t995_transfer_logs_km_chk check (out_km between 0 and 300 and back_km between 0 and 300),
  constraint t995_transfer_logs_min_chk check (minutes is null or minutes in (30,60,90,120))
);
comment on table public.t995_transfer_logs is '調撥工時查詢 v2 當日調撥紀錄；只留 7 天，只經 t995_transfer_* 函式存取。';
create index if not exists t995_transfer_logs_date_idx on public.t995_transfer_logs (log_date, created_at);

create table if not exists public.t995_transfer_settings (
  id integer primary key default 1 check (id = 1),
  password_hash text
);
comment on table public.t995_transfer_settings is '調撥紀錄值班密碼（bcrypt 雜湊）；由美花在 SQL Editor 設定。';
insert into public.t995_transfer_settings (id) values (1) on conflict (id) do nothing;

alter table public.t995_transfer_logs enable row level security;
alter table public.t995_transfer_settings enable row level security;
revoke all on public.t995_transfer_logs from anon, authenticated;
revoke all on public.t995_transfer_settings from anon, authenticated;

-- 內部：檢查密碼
create or replace function public.t995_transfer_pw_ok(p_password text)
returns boolean language plpgsql security definer set search_path = '' as $$
declare h text;
begin
  select password_hash into h from public.t995_transfer_settings where id = 1;
  if h is null or p_password is null or length(p_password) = 0 then return false; end if;
  if extensions.crypt(p_password, h) = h then return true; end if;
  perform pg_sleep(1);
  return false;
end $$;
revoke all on function public.t995_transfer_pw_ok(text) from public, anon, authenticated;

-- 確認密碼（網頁登入用）
create or replace function public.t995_transfer_check(p_password text)
returns boolean language plpgsql security definer set search_path = '' as $$
begin
  return public.t995_transfer_pw_ok(p_password);
end $$;

-- 讀取某一天的紀錄（只限最近 7 天，大家都能看）
create or replace function public.t995_transfer_list(p_date date)
returns table (id uuid, log_date date, created_at timestamptz, from_code text, from_name text, to_code text, to_name text, out_km numeric, back_km numeric, minutes integer)
language sql security definer set search_path = '' stable as $$
  select l.id, l.log_date, l.created_at, l.from_code, l.from_name, l.to_code, l.to_name, l.out_km, l.back_km, l.minutes
  from public.t995_transfer_logs l
  where l.log_date = p_date
    and p_date >= (now() at time zone 'Asia/Taipei')::date - 6
  order by l.created_at;
$$;

-- 新增一筆（要密碼；日期一律用台北今天）
create or replace function public.t995_transfer_add(p_password text, p_from_code text, p_from_name text, p_to_code text, p_to_name text, p_out_km numeric, p_back_km numeric, p_minutes integer)
returns uuid language plpgsql security definer set search_path = '' as $$
declare new_id uuid;
begin
  if not public.t995_transfer_pw_ok(p_password) then raise exception 'BAD_PASSWORD' using errcode = '28P01'; end if;
  insert into public.t995_transfer_logs (from_code, from_name, to_code, to_name, out_km, back_km, minutes)
  values (upper(p_from_code), p_from_name, upper(p_to_code), p_to_name, p_out_km, p_back_km, p_minutes)
  returning id into new_id;
  return new_id;
end $$;

-- 刪除一筆（要密碼）
create or replace function public.t995_transfer_delete(p_password text, p_id uuid)
returns boolean language plpgsql security definer set search_path = '' as $$
begin
  if not public.t995_transfer_pw_ok(p_password) then raise exception 'BAD_PASSWORD' using errcode = '28P01'; end if;
  delete from public.t995_transfer_logs where id = p_id;
  return found;
end $$;

revoke all on function public.t995_transfer_check(text) from public;
revoke all on function public.t995_transfer_list(date) from public;
revoke all on function public.t995_transfer_add(text,text,text,text,text,numeric,numeric,integer) from public;
revoke all on function public.t995_transfer_delete(text,uuid) from public;
grant execute on function public.t995_transfer_check(text) to anon, authenticated;
grant execute on function public.t995_transfer_list(date) to anon, authenticated;
grant execute on function public.t995_transfer_add(text,text,text,text,text,numeric,numeric,integer) to anon, authenticated;
grant execute on function public.t995_transfer_delete(text,uuid) to anon, authenticated;

-- 每天 00:05（台北 = UTC 16:05）刪除 7 天前的紀錄
select cron.schedule('t995_transfer_logs_retention_7d', '5 16 * * *',
  $$delete from public.t995_transfer_logs where log_date < (now() at time zone 'Asia/Taipei')::date - 6$$);


-- ===== 實際套用的軟刪除版（取代上面的 list / delete）=====
alter table public.t995_transfer_logs add column if not exists deleted_at timestamptz;
-- list 多加條件：and l.deleted_at is null
-- delete 改為：update public.t995_transfer_logs set deleted_at = now() where id = p_id and deleted_at is null;
