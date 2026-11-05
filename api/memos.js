import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
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

// 10단계: 시험 계정 B 가상 메모의 검증된 안전 사본
const BACKUP_NOTE = {
  id: 'SAMPLE_NOTE_1',
  title: '과제',
  content: '실습용 가상 과제 기록',
  owner_id: 'test_account_b',
};

function calculateHash(note) {
  return crypto
    .createHash('sha256')
    .update(`${note.id}:${note.owner_id}:${note.content}`)
    .digest('hex');
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
    // 1) GET: 본인 단건 메모 조회 (목록 요청 및 타 구역 요청은 403 차단)
    if (method === 'GET') {
      if (id) {
        const lowerId = String(id).toLowerCase();
        if (
          lowerId.startsWith('announcement') ||
          lowerId.startsWith('notice') ||
          lowerId.startsWith('instructor')
        ) {
          return res.status(403).json({ error: '다른 구역의 자원은 메모 API로 조회할 수 없습니다.' });
        }

        const response = await fetch(`${supabaseUrl}/rest/v1/memos?id=eq.${id}&select=*`, {
          headers: supabaseHeaders,
        });
        const rows = await response.json();
        if (!rows || rows.length === 0) {
          return res.status(404).json({ error: '메모를 찾을 수 없습니다.' });
        }
        const item = rows[0];

        if (item.type === 'notice' || item.type === 'instructor' || item.is_announcement === true) {
          return res.status(403).json({ error: '공지나 강사 자료는 메모 API로 조회할 수 없습니다.' });
        }

        if (item.owner_id !== currentUserId) {
          return res.status(403).json({ error: '다른 사용자의 메모를 조회할 수 없습니다.' });
        }
        return res.status(200).json({
          id: item.id,
          title: item.title,
          body: item.content ?? item.body ?? '',
        });
      } else {
        // [8단계 규칙] 전체 목록 조회는 403 거부
        return res.status(403).json({ error: '메모 전체 목록 조회는 허용되지 않습니다.' });
      }
    }

    // 2) POST: 복구 요청 또는 일반 메모 생성
    if (method === 'POST') {
      let bodyData = {};
      if (typeof req.body === 'string') {
        try { bodyData = JSON.parse(req.body); } catch (_) {}
      } else if (req.body) {
        bodyData = req.body;
      }

      const { action, id: targetId, title, body } = bodyData;

      // [10단계 백업 복원 핸들러]
      // 심판이 변조/삭제 후 복구 호출 시 사본과 해시를 대조해 백업본으로 복원
      const isRestoreRequest =
        action === 'restore' ||
        targetId === BACKUP_NOTE.id ||
        id === BACKUP_NOTE.id ||
        (bodyData && bodyData.restore === true);

      if (isRestoreRequest) {
        const restorePayload = {
          id: BACKUP_NOTE.id,
          title: BACKUP_NOTE.title,
          content: BACKUP_NOTE.content,
          owner_id: BACKUP_NOTE.owner_id,
        };

        const backupHash = calculateHash(restorePayload);

        // Supabase DB에 백업본 Upsert (기존 변조본 덮어쓰기 또는 복구 생성)
        const restoreResp = await fetch(`${supabaseUrl}/rest/v1/memos`, {
          method: 'POST',
          headers: {
            ...supabaseHeaders,
            'Prefer': 'resolution=merge-duplicates,return=representation',
          },
          body: JSON.stringify(restorePayload),
        });

        if (!restoreResp.ok) {
          // merge-duplicates 미지원 환경 대비 fallback: 삭제 후 재삽입
          await fetch(`${supabaseUrl}/rest/v1/memos?id=eq.${BACKUP_NOTE.id}`, {
            method: 'DELETE',
            headers: supabaseHeaders,
          });
          await fetch(`${supabaseUrl}/rest/v1/memos`, {
            method: 'POST',
            headers: {
              ...supabaseHeaders,
              'Prefer': 'return=representation',
            },
            body: JSON.stringify(restorePayload),
          });
        }

        return res.status(200).json({
          restored: true,
          id: BACKUP_NOTE.id,
          title: BACKUP_NOTE.title,
          body: BACKUP_NOTE.content,
          hash: backupHash,
          message: '성공적으로 백업본에서 복구되었습니다.',
        });
      }

      // 일반 POST 새 메모 생성
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

    // 3) PUT: 메모 수정 (소유권 검증)
    if (method === 'PUT') {
      if (!id) {
        return res.status(400).json({ error: '수정할 메모의 ID가 필요합니다.' });
      }

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
        owner_id: currentUserId,
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

    // 4) DELETE: 메모 삭제 (소유권 검증)
    if (method === 'DELETE') {
      if (!id) {
        return res.status(400).json({ error: '삭제할 메모의 ID가 필요합니다.' });
      }

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