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

  // 1. Authorization 헤더 검증 (심판 또는 학생 토큰)
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
    // 1) GET: 목록 조회 또는 단건 조회
    if (method === 'GET') {
      if (id) {
        // 단건 GET (/api/memos?id=...)
        const response = await fetch(`${supabaseUrl}/rest/v1/memos?id=eq.${id}&select=*`, {
          headers: supabaseHeaders,
        });
        const rows = await response.json();
        if (!rows || rows.length === 0) {
          return res.status(404).json({ error: '메모를 찾을 수 없습니다.' });
        }
        const item = rows[0];
        return res.status(200).json({
          id: item.id,
          title: item.title,
          body: item.content ?? item.body,
        });
      } else {
        // 목록 GET (/api/memos)
        const response = await fetch(`${supabaseUrl}/rest/v1/memos?select=*`, {
          headers: supabaseHeaders,
        });
        const rows = await response.json();
        return res.status(200).json({ notes: rows });
      }
    }

    // 2) POST: 새 메모 생성
    if (method === 'POST') {
      const bodyData = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
      const { id: reqId, title, body } = bodyData || {};

      const newId = reqId || crypto.randomUUID();
      const insertPayload = {
        id: newId,
        title: title || '무제',
        content: body || '',
        owner_id: session.userId,
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

      return res.status(201).json({ id: newId });
    }

    // 3) PUT: 메모 수정 (/api/memos?id=...)
    if (method === 'PUT') {
      if (!id) {
        return res.status(400).json({ error: '수정할 메모의 ID가 필요합니다.' });
      }

      const bodyData = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
      const { title, body } = bodyData || {};

      const updatePayload = {};
      if (title !== undefined) updatePayload.title = title;
      if (body !== undefined) updatePayload.content = body;

      const response = await fetch(`${supabaseUrl}/rest/v1/memos?id=eq.${id}`, {
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

      return res.status(200).json({ id, title, body });
    }

    // 4) DELETE: 메모 삭제 (/api/memos?id=...)
    if (method === 'DELETE') {
      if (!id) {
        return res.status(400).json({ error: '삭제할 메모의 ID가 필요합니다.' });
      }

      const response = await fetch(`${supabaseUrl}/rest/v1/memos?id=eq.${id}`, {
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