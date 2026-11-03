export default async function handler(req, res) {
  // 1. CORS 및 POST 메서드 검증
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version'
  );

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  // 2. Vercel 환경 변수 가져오기 (SUPABASE_ANON_KEY 사용)
  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseAnonKey = process.env.SUPABASE_ANON_KEY;

  if (!supabaseUrl || !supabaseAnonKey) {
    return res.status(500).json({ error: 'Server configuration error: Missing environment variables' });
  }

  try {
    // 3. Supabase Auth REST API 호출
    const response = await fetch(`${supabaseUrl}/auth/v1/token?grant_type=password`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'apikey': supabaseAnonKey,
      },
      body: JSON.stringify({ email, password }),
    });

    const data = await response.json();

    // 4. 인증 실패 시 Supabase 에러 메시지 반환
    if (!response.ok) {
      return res.status(response.status).json({ 
        error: data.error_description || data.msg || data.message || 'Login failed' 
      });
    }

    // 5. 로그인 성공 시 토큰 및 유저 정보 반환
    return res.status(200).json(data);
  } catch (err) {
    console.error('Login API Error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
}