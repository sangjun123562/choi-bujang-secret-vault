import fs from 'node:fs';
import path from 'node:path';
import { createLoginVerifier } from '../src/verify-login.mjs';

// aleph.config.json 로드
const configPath = path.resolve(process.cwd(), 'aleph.config.json');
const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));

let verifier = null;

function getVerifier() {
  if (!verifier) {
    verifier = createLoginVerifier({
      config,
      supabaseSecretKey: process.env.SUPABASE_SECRET_KEY,
    });
  }
  return verifier;
}

export default async function handler(req, res) {
  const method = req.method;
  const allowedMethods = ['GET', 'POST', 'PUT', 'DELETE'];
  if (!allowedMethods.includes(method)) {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  // 1. Authorization 헤더 검증
  const authHeader = req.headers.authorization || req.headers.Authorization;
  if (!authHeader) {
    return res.status(401).json({ error: '인증 토큰이 누락되었습니다.' });
  }

  let verifyAuth;
  try {
    verifyAuth = getVerifier();
  } catch (err) {
    return res.status(500).json({ error: '검증기 초기화 실패: ' + err.message });
  }

  const session = await verifyAuth(authHeader);
  if (!session || !session.userId) {
    return res.status(403).json({ error: '유효하지 않거나 만료된 토큰입니다.' });
  }

  const currentUserId = session.userId;
  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;

  if (!supabaseUrl || !supabaseSecretKey) {
    return res.status(500).json({ error: 'Supabase 환경변수가 설정되지 않았습니다.' });
  }

  const supabaseHeaders = {
    'apikey': supabaseSecretKey,
    'Authorization': `Bearer ${supabaseSecretKey}`,
    'Content-Type': 'application/json',
  };

  const { id } = req.query;

  try {
    // 1) GET: 본인 메모 목록 또는 본인 소유의 단건 조회
    if (method === 'GET') {
      if (id) {
        // 단건 GET: 메모 존재 여부 및 소유자 확인
        const response = await fetch(`${supabaseUrl}/rest/v1/memos?id=eq.${id}&select=*`, {
          headers: supabaseHeaders,
        });
        const rows = await response.json();
        if (!rows || rows.length === 0) {
          return res.status(404).json({ error: '메모를 찾을 수 없습니다.' });
        }
        const item = rows[0];
        if (item.owner_id !== currentUserId) {
          return res.status(403).json({ error: '다른 사용자의 메모를 조회할 수 없습니다.' });
        }
        return res.status(200).json({
          id: item.id,
          title: item.title,
          body: item.content ?? item.body ?? '',
        });
      } else {
        // 목록 GET: 본인 소유(owner_id == currentUserId) 메모만 조회
        const response = await fetch(`${supabaseUrl}/rest/v1/memos?owner_id=eq.${currentUserId}&select=*`, {
          headers: supabaseHeaders,
        });
        const rows = await response.json();
        const mappedNotes = (rows || []).map(r => ({
          id: r.id,
          title: r.title,
          body: r.content ?? r.body ?? '',
        }));
        return res.status(200).json({ notes: mappedNotes });
      }
    }

    // 2) POST: 새 메모 생성 (URL/본문의 owner_id는 무시하고 토큰의 userId로 강제 저장)
    if (method === 'POST') {
      const bodyData = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
      const { title, body } = bodyData || {};

      const insertPayload = {
        title: title || '무제',
        content: body || '',
        owner_id: currentUserId,
      };

      const response = await fetch(`${supabaseUrl}/rest/v1/memos`, {
        method: 'POST',
        headers: {
          ...supabaseHeaders,
          'Prefer': 'return=representation',
        },
        body: JSON.stringify(insertPayload),
      });

      if (!response.ok) {
        return res.status(response.status).json({ error: '메모 생성 실패' });
      }

      const created = await response.json();
      const newMemo = created[0];
      return res.status(201).json({
        id: newMemo.id,
        title: newMemo.title,
        body: newMemo.content ?? newMemo.body ?? '',
      });
    }

    // 3) PUT: 메모 수정 (기존 행 소유자 확인 및 본인만 수정 허용)
    if (method === 'PUT') {
      if (!id) {
        return res.status(400).json({ error: '수정할 메모의 ID가 필요합니다.' });
      }

      // 기존 메모 소유권 확인
      const checkResp = await fetch(`${supabaseUrl}/rest/v1/memos?id=eq.${id}&select=*`, {
        headers: supabaseHeaders,
      });
      const checkRows = await checkResp.json();
      if (!checkRows || checkRows.length === 0) {
        return res.status(404).json({ error: '메모를 찾을 수 없습니다.' });
      }
      if (checkRows[0].owner_id !== currentUserId) {
        return res.status(403).json({ error: '다른 사용자의 메모를 수정할 수 없습니다.' });
      }

      const bodyData = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
      const { title, body } = bodyData || {};

      const updatePayload = {
        owner_id: currentUserId, // 소유자 변조 방지 (본인 고정)
      };
      if (title !== undefined) updatePayload.title = title;
      if (body !== undefined) updatePayload.content = body;

      const response = await fetch(`${supabaseUrl}/rest/v1/memos?id=eq.${id}&owner_id=eq.${currentUserId}`, {
        method: 'PATCH',
        headers: {
          ...supabaseHeaders,
          'Prefer': 'return=representation',
        },
        body: JSON.stringify(updatePayload),
      });

      if (!response.ok) {
        return res.status(response.status).json({ error: '메모 수정 실패' });
      }

      const updated = await response.json();
      const item = updated[0];
      return res.status(200).json({
        id: item.id,
        title: item.title,
        body: item.content ?? item.body ?? '',
      });
    }

    // 4) DELETE: 메모 삭제 (기존 행 소유자 확인 후 본인만 삭제 허용)
    if (method === 'DELETE') {
      if (!id) {
        return res.status(400).json({ error: '삭제할 메모의 ID가 필요합니다.' });
      }

      // 기존 메모 소유권 확인
      const checkResp = await fetch(`${supabaseUrl}/rest/v1/memos?id=eq.${id}&select=*`, {
        headers: supabaseHeaders,
      });
      const checkRows = await checkResp.json();
      if (!checkRows || checkRows.length === 0) {
        return res.status(404).json({ error: '메모를 찾을 수 없습니다.' });
      }
      if (checkRows[0].owner_id !== currentUserId) {
        return res.status(403).json({ error: '다른 사용자의 메모를 삭제할 수 없습니다.' });
      }

      const response = await fetch(`${supabaseUrl}/rest/v1/memos?id=eq.${id}&owner_id=eq.${currentUserId}`, {
        method: 'DELETE',
        headers: supabaseHeaders,
      });

      if (!response.ok) {
        return res.status(response.status).json({ error: '메모 삭제 실패' });
      }

      return res.status(200).json({ message: '삭제되었습니다.' });
    }
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
}