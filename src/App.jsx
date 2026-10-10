import { useState } from 'react';
import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000';

function App() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [accessToken, setAccessToken] = useState('');
  const [data, setData] = useState('');
  const [error, setError] = useState('');

  const login = async (event) => {
    event.preventDefault();
    setError('');
    try {
      const res = await axios.post(
        `${API_URL}/login`,
        { username, password },
        { withCredentials: true }
      );
      setAccessToken(res.data.accessToken);
    } catch (err) {
      setError(err.response?.data?.error || 'Login failed. Check the API connection and credentials.');
    }
  };

  const fetchProtectedData = async () => {
    setError('');
    try {
      const res = await axios.get(`${API_URL}/protected`, {
        headers: { Authorization: `Bearer ${accessToken}` },
        withCredentials: true
      });
      setData(res.data.message);
    } catch (err) {
      if (err.response?.status === 401) {
        try {
          const refreshRes = await axios.post(`${API_URL}/refresh`, {}, { withCredentials: true });
          const newToken = refreshRes.data.accessToken;
          setAccessToken(newToken);
          const retry = await axios.get(`${API_URL}/protected`, {
            headers: { Authorization: `Bearer ${newToken}` },
            withCredentials: true
          });
          setData(retry.data.message);
        } catch {
          setAccessToken('');
          setData('');
          setError('Session expired. Please log in again.');
        }
      } else {
        setError(err.response?.data?.error || 'Access denied. Check the API connection.');
      }
    }
  };

  const logout = async () => {
    setError('');
    try {
      await axios.post(`${API_URL}/logout`, {}, { withCredentials: true });
    } catch (err) {
      setError(err.response?.data?.error || 'Logout request failed.');
    } finally {
      setAccessToken('');
      setData('');
    }
  };

  return (
    <main>
      <form onSubmit={login}>
        <label>
          Username
          <input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" required />
        </label>
        <label>
          Password
          <input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" required />
        </label>
        <button type="submit">Login</button>
      </form>
      <div className="btns">
        <button onClick={fetchProtectedData} disabled={!accessToken}>Fetch Protected Data</button>
        <button onClick={logout}>Logout</button>
      </div>
      {error && <p role="alert">{error}</p>}
      {data && <p>{data}</p>}
    </main>
  );
}

export default App;