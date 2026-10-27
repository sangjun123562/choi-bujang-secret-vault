export default async function handler(req, res) {
  // GET 요청(조회)만 허용
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;

  if (!supabaseUrl || !supabaseSecretKey) {
    return res.status(500).json({ error: 'Supabase 환경변수 설정이 누락되었습니다.' });
  }

  try {
    // Supabase REST API 호출: memos 테이블 전체 조회
    const response = await fetch(`${supabaseUrl}/rest/v1/memos?select=*`, {
      headers: {
        'apikey': supabaseSecretKey,
        'Authorization': `Bearer ${supabaseSecretKey}`
      }
    });

    if (!response.ok) {
      return res.status(response.status).json({ error: 'Supabase 데이터 조회 실패' });
    }

    const rows = await response.json();

    // 1단계 프론트엔드가 { notes: [...] } 구조를 쓰는지, 배열 자체를 쓰는지에 맞춰 반환
    // notes 객체 형태와 배열 형태를 둘 다 지원하도록 포맷팅
    return res.status(200).json({
      notes: rows
    });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
}