import { createLoginVerifier } from '../src/verify-login.mjs';
import config from '../aleph.config.json' with { type: 'json' };
import { createClient } from '@supabase/supabase-js';

// 서버 검증에는 Service Role / Secret Key가 필요합니다.
const secretKey = process.env.SUPABASE_SECRET_KEY;
// DB 클라이언트는 등록된 키 중 유효한 것을 가져옵니다.
const supabaseKey = process.env.SUPABASE_ANON_KEY || process.env.SUPABASE_SECRET_KEY;
const supabaseUrl = process.env.SUPABASE_URL;

const verifyLoginAuthorization = createLoginVerifier({
  config,
  supabaseSecretKey: secretKey,
});

const supabase = createClient(supabaseUrl, supabaseKey);

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version, Authorization'
  );

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  // 1. 로그인 여부 및 토큰 검사 (서버 검증 사용자 ID 확보)
  const authHeader = req.headers['authorization'];
  const authResult = await verifyLoginAuthorization(authHeader);

  if (!authResult) {
    return res.status(401).json({ error: 'Unauthorized: 로그인이 필요합니다.' });
  }

  const userId = authResult.userId;
  const { id } = req.query;

  try {
    // --- [GET] /api/memos (목록 조회 - 본인 소유만) ---
    if (req.method === 'GET' && !id) {
      const { data, error } = await supabase
        .from('memos')
        .select('id, content')
        .eq('owner_id', userId);

      if (error) {
        console.error('Supabase GET Error:', error);
        return res.status(500).json({ error: error.message });
      }
      return res.status(200).json(data ?? []);
    }

    // --- [POST] /api/memos (메모 생성 - 검증된 userId 강제 매핑) ---
    if (req.method === 'POST') {
      const { content } = req.body || {};
      if (typeof content !== 'string' || !content.trim()) {
        return res.status(400).json({ error: 'content is required' });
      }

      const { data, error } = await supabase
        .from('memos')
        .insert([{ content, owner_id: userId }])
        .select('id, content')
        .single();

      if (error) {
        console.error('Supabase POST Error:', error);
        return res.status(500).json({ error: error.message });
      }
      return res.status(200).json(data);
    }

    if (!id) {
      return res.status(400).json({ error: 'Memo ID is required' });
    }

    // --- [GET] /api/memos/:id (단건 조회 - 본인 소유만) ---
    if (req.method === 'GET') {
      const { data, error } = await supabase
        .from('memos')
        .select('id, content')
        .eq('id', id)
        .eq('owner_id', userId)
        .maybeSingle();

      if (error) {
        console.error('Supabase GET Single Error:', error);
        return res.status(500).json({ error: error.message });
      }
      if (!data) return res.status(404).json({ error: 'Not found' });

      return res.status(200).json(data);
    }

    // --- [PUT] /api/memos/:id (메모 수정 - 본인 소유 행만) ---
    if (req.method === 'PUT') {
      const { content } = req.body || {};
      if (typeof content !== 'string' || !content.trim()) {
        return res.status(400).json({ error: 'content is required' });
      }

      const { data, error } = await supabase
        .from('memos')
        .update({ content })
        .eq('id', id)
        .eq('owner_id', userId)
        .select('id, content')
        .maybeSingle();

      if (error) {
        console.error('Supabase PUT Error:', error);
        return res.status(500).json({ error: error.message });
      }
      if (!data) return res.status(404).json({ error: 'Not found' });

      return res.status(200).json(data);
    }

    // --- [DELETE] /api/memos/:id (메모 삭제 - 본인 소유 행만) ---
    if (req.method === 'DELETE') {
      const { data, error } = await supabase
        .from('memos')
        .delete()
        .eq('id', id)
        .eq('owner_id', userId)
        .select('id');

      if (error) {
        console.error('Supabase DELETE Error:', error);
        return res.status(500).json({ error: error.message });
      }
      if (!data || data.length === 0) return res.status(404).json({ error: 'Not found' });

      return res.status(200).json({ success: true });
    }

    return res.status(405).json({ error: 'Method not allowed' });
  } catch (err) {
    console.error('API Catch Error:', err);
    return res.status(500).json({ error: 'Internal server error', details: err.message });
  }
}