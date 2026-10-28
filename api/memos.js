import { randomUUID } from 'node:crypto';
import { createLoginVerifier } from '../src/verify-login.mjs';
import config from '../aleph.config.json';
import { createClient } from '@supabase/supabase-js';

const verifyLoginAuthorization = createLoginVerifier({
  config,
  supabaseSecretKey: process.env.SUPABASE_SECRET_KEY,
});

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SECRET_KEY
);

export default async function handler(req, res) {
  // 1. 로그인 여부 및 토큰 검사 (서버 검증 사용자 ID 확보)
  const authHeader = req.headers['authorization'];
  const authResult = await verifyLoginAuthorization(authHeader);

  if (!authResult) {
    return res.status(401).json({ error: 'Unauthorized: 로그인이 필요합니다.' });
  }

  const userId = authResult.userId;
  const { id } = req.query;

  // --- [GET] /api/memos (목록 조회 - 본인 소유만) ---
  if (req.method === 'GET' && !id) {
    const { data, error } = await supabase
      .from('memos')
      .select('id, title, body')
      .eq('owner_id', userId);

    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json(data ?? []);
  }

  // --- [POST] /api/memos (메모 생성 - 검증된 userId 강제 매핑) ---
  if (req.method === 'POST') {
    const { id: reqId, title, body } = req.body || {};
    const memoId = reqId || randomUUID();

    const { data, error } = await supabase
      .from('memos')
      .insert([{ id: memoId, title, body, owner_id: userId }]) // 본인 ID 강제 적용
      .select('id, title, body')
      .single();

    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json(data);
  }

  if (!id) {
    return res.status(400).json({ error: 'Memo ID is required' });
  }

  // --- [GET] /api/memos/:id (단건 조회 - 본인 소유만) ---
  if (req.method === 'GET') {
    const { data, error } = await supabase
      .from('memos')
      .select('id, title, body')
      .eq('id', id)
      .eq('owner_id', userId)
      .maybeSingle();

    if (error) return res.status(500).json({ error: error.message });
    if (!data) return res.status(404).json({ error: 'Not found' });

    return res.status(200).json(data);
  }

  // --- [PUT] /api/memos/:id (메모 수정 - 본인 소유 행만) ---
  if (req.method === 'PUT') {
    const { title, body } = req.body || {};
    const { data, error } = await supabase
      .from('memos')
      .update({ title, body })
      .eq('id', id)
      .eq('owner_id', userId) // 기존 행의 소유자가 본인인지 확인
      .select('id, title, body')
      .maybeSingle();

    if (error) return res.status(500).json({ error: error.message });
    if (!data) return res.status(404).json({ error: 'Not found' });

    return res.status(200).json(data);
  }

  // --- [DELETE] /api/memos/:id (메모 삭제 - 본인 소유 행만) ---
  if (req.method === 'DELETE') {
    const { data, error } = await supabase
      .from('memos')
      .delete()
      .eq('id', id)
      .eq('owner_id', userId) // 삭제 대상 소유자가 본인인지 확인
      .select('id');

    if (error) return res.status(500).json({ error: error.message });
    if (!data || data.length === 0) return res.status(404).json({ error: 'Not found' });

    return res.status(200).json({ success: true });
  }

  return res.status(405).json({ error: 'Method not allowed' });
}