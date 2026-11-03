// 1) GET: 본인 메모 목록 또는 본인 소유의 단건 조회
    if (method === 'GET') {
      if (id) {
        // [8단계 방어] 강사 자료나 공지사항 등 다른 구역 ID를 API로 직접 조회하는 시도 차단
        const lowerId = String(id).toLowerCase();
        if (
          lowerId.startsWith('announcement') ||
          lowerId.startsWith('notice') ||
          lowerId.startsWith('instructor')
        ) {
          return res.status(403).json({ error: '다른 구역의 자원은 메모 API로 조회할 수 없습니다.' });
        }

        // 단건 GET: 메모 존재 여부 및 소유자 확인
        const response = await fetch(`${supabaseUrl}/rest/v1/memos?id=eq.${id}&select=*`, {
          headers: supabaseHeaders,
        });
        const rows = await response.json();
        if (!rows || rows.length === 0) {
          return res.status(404).json({ error: '메모를 찾을 수 없습니다.' });
        }
        const item = rows[0];

        // [8단계 방어] 강사 권한/타 구역 데이터 또는 본인 소유가 아닌 경우 차단
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
        // [8단계 방어] 메모 전체 목록 요청은 403으로 차단
        return res.status(403).json({ error: '메모 전체 목록 조회는 허용되지 않습니다.' });
      }
    }