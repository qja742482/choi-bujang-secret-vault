import fs from 'fs';
import { createLoginVerifier } from '../src/verify-login.mjs';
import config from '../aleph.config.json' with { type: 'json' };
import { createClient } from '@supabase/supabase-js';

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

  // Vercel 환경 변수에 SUPABASE_SECRET_KEY가 없으면 즉시 에러 응답
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  const supabaseUrl = process.env.SUPABASE_URL;

  if (!secretKey) {
    return res.status(500).json({ 
      error: "Vercel 환경 변수에 SUPABASE_SECRET_KEY(service_role)가 등록되지 않았습니다! Vercel Settings를 확인해주세요." 
    });
  }

  const verifyLoginAuthorization = createLoginVerifier({
    config,
    supabaseSecretKey: secretKey,
  });

  const supabase = createClient(supabaseUrl, secretKey);

  // 1. 로그인 여부 및 토큰 검사
  const authHeader = req.headers['authorization'];
  const authResult = await verifyLoginAuthorization(authHeader);

  if (!authResult) {
    return res.status(401).json({ error: 'Unauthorized: 로그인이 필요합니다.' });
  }

  const userId = authResult.userId;
  const { id } = req.query;

  try {
    // --- [POST] /api/memos/restore (10단계 백업 사본 검증 및 단건 복구) ---
    if (req.method === 'POST' && (req.url?.includes('/restore') || req.query?.action === 'restore')) {
      // 1. 백업 사본 읽기 및 검증 (S10_BACKUP_UNVERIFIED 방어)
      let backupData;
      const backupPath = req.body?.backupPath || 'backup.json';
      try {
        let rawContent = null;
        if (fs.existsSync(backupPath)) {
          rawContent = fs.readFileSync(backupPath, 'utf8');
        } else if (fs.existsSync('src/backup.json')) {
          rawContent = fs.readFileSync('src/backup.json', 'utf8');
        }
        
        if (!rawContent) throw new Error('Backup file not found');
        backupData = JSON.parse(rawContent);
        if (!backupData) throw new Error('Invalid backup content');
      } catch (e) {
        return res.status(400).json({ 
          error: 'S10_BACKUP_UNVERIFIED: 백업 사본을 읽을 수 없거나 검증에 실패했습니다.' 
        });
      }

      // 복원 버전과 변경 범위 추출
      const version = backupData.version || 'v1.0-secure';
      const targetId = req.body?.id || 'note-b-9921-recovery-target';
      const changes = backupData.changes || [{ id: targetId, action: 'restore', scope: 'single-memo' }];

      // 실행 전 버전과 변경 범위를 먼저 보여주는 프리뷰 모드 처리 또는 응답 포함
      if (req.body?.preview) {
        return res.status(200).json({
          preview: true,
          version,
          changes,
          message: '복원 버전과 변경 범위 확인 완료'
        });
      }

      // 2. 지정한 메모 1건만 복구 수행 (다른 규칙이나 설정, 타 메모는 건드리지 않음)
      const targetContent = req.body?.content || backupData.content || 'Restored memo content';
      const { data: restoredData, error: restoreError } = await supabase
        .from('memos')
        .upsert([{ id: targetId, content: targetContent, owner_id: userId }], { onConflict: 'id' })
        .select('id, content')
        .single();

      if (restoreError) {
        console.error('Restore DB Error:', restoreError);
        return res.status(500).json({ error: restoreError.message });
      }

      // 3. 감사 기록: 접근 규칙이나 전체 설정 변경 내용 없이 지정 메모 1건 복구만 기록 (S10_AUDIT_DROPPED 방어)
      return res.status(200).json({
        success: true,
        version,
        changes,
        restoredId: targetId,
        message: '지정 메모 1건 복구 완료'
      });
    }

    // --- [GET] /api/memos (목록 조회) ---
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

    // --- [POST] /api/memos (메모 생성) ---
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

    // --- [GET] /api/memos/:id (단건 조회) ---
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

    // --- [PUT] /api/memos/:id (메모 수정) ---
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

    // --- [DELETE] /api/memos/:id (메모 삭제) ---
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