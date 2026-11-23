-- 2026-11-23 加：每筆紀錄可由值班指定「申請餐廳」，網頁整理各申請餐廳當日工時。
-- 只新增欄位與函式，原本的 t995_transfer_list / add / delete 不動（舊網頁照樣能用）。

alter table public.t995_transfer_logs add column if not exists req_code text;
alter table public.t995_transfer_logs add column if not exists req_name text;
alter table public.t995_transfer_logs drop constraint if exists t995_transfer_logs_req_chk;
alter table public.t995_transfer_logs add constraint t995_transfer_logs_req_chk
  check ((req_code is null and req_name is null)
      or (req_code ~ '^TW[A-Z][0-9]{3}$' and length(req_name) between 1 and 40));

-- 讀取某一天的紀錄（含申請餐廳）
create or replace function public.t995_transfer_list2(p_date date)
returns table (id uuid, log_date date, created_at timestamptz, from_code text, from_name text, to_code text, to_name text,
               out_km numeric, back_km numeric, minutes integer, req_code text, req_name text)
language sql security definer set search_path = '' stable as $$
  select l.id, l.log_date, l.created_at, l.from_code, l.from_name, l.to_code, l.to_name, l.out_km, l.back_km, l.minutes, l.req_code, l.req_name
  from public.t995_transfer_logs l
  where l.log_date = p_date
    and l.deleted_at is null
    and p_date >= (now() at time zone 'Asia/Taipei')::date - 6
  order by l.created_at;
$$;

-- 設定／清除某筆的申請餐廳（要值班密碼；p_req_code 傳 null 為清除）
create or replace function public.t995_transfer_set_req(p_password text, p_id uuid, p_req_code text, p_req_name text)
returns boolean language plpgsql security definer set search_path = '' as $$
begin
  if not public.t995_transfer_pw_ok(p_password) then raise exception 'BAD_PASSWORD' using errcode = '28P01'; end if;
  update public.t995_transfer_logs
     set req_code = case when p_req_code is null then null else upper(p_req_code) end,
         req_name = case when p_req_code is null then null else p_req_name end
   where id = p_id and deleted_at is null;
  return found;
end $$;

revoke all on function public.t995_transfer_list2(date) from public;
revoke all on function public.t995_transfer_set_req(text,uuid,text,text) from public;
grant execute on function public.t995_transfer_list2(date) to anon, authenticated;
grant execute on function public.t995_transfer_set_req(text,uuid,text,text) to anon, authenticated;
