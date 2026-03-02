create table if not exists shops (
  id bigserial primary key,
  shop_domain text not null unique,
  shopify_access_token text not null,
  created_at timestamptz not null default now()
);

create table if not exists settings (
  id bigserial primary key,
  shop_domain text not null unique references shops(shop_domain) on delete cascade,
  neosys_user text not null,
  neosys_pass text not null,
  neosys_base_url text not null default 'https://api.neosys.ro',
  default_gestiune_id text,
  default_punct_lucru_id text,
  default_shopify_location_id text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists idempotency (
  id bigserial primary key,
  key text not null unique,
  status text not null default 'processing',
  meta jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);