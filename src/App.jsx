import { useState } from 'react';
import axios from 'axios';

function App() {
  const [accessToken, setAccessToken] = useState('');
  const [data, setData] = useState('');

  const login = async () => {
    try {
      const res = await axios.post(
        'http://localhost:5000/login',
        { username: 'dio@gmail.com', password: '1234' },
        { withCredentials: true } // Send cookies
      );
      setAccessToken(res.data.accessToken);
    } catch (err) {
      alert(err.response?.data?.error || 'Login failed');
    }
  };

  const fetchProtectedData = async () => {
    try {
      const res = await axios.get('http://localhost:5000/protected', {
        headers: { Authorization: `Bearer ${accessToken}` },
        withCredentials: true
      });
      setData(res.data.message);
    } catch (err) {
      if (err.response?.status === 401) {
        // Token expired? Try to refresh
        try {
          const refreshRes = await axios.post(
            'http://localhost:5000/refresh',
            {},
            { withCredentials: true }
          );
          setAccessToken(refreshRes.data.accessToken);
          // Retry original request
          fetchProtectedData();
        } catch (refreshErr) {
          alert('Session expired. Please login again.');
        }
      } else {
        alert(err.response?.data?.error || 'Access denied');
      }
    }
  };

  const logout = async () => {
    await axios.post(
      'http://localhost:5000/logout',
      {},
      { withCredentials: true }
    );
    setAccessToken('');
    setData('');
  };

  return (
    <div>
      <button onClick={login}>Login</button>
      <button onClick={fetchProtectedData}>Fetch Protected Data</button>
      <button onClick={logout}>Logout</button>
      {data && <p>{data}</p>}
    </div>
  );
}

export default App;