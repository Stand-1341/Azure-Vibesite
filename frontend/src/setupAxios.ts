/// <reference types="node" />
import axios, { InternalAxiosRequestConfig } from 'axios';

const JWT_TOKEN_STORAGE_KEY = 'aegisAuthToken';

const configuredApiUrl = process.env.REACT_APP_API_URL?.trim();
const apiBaseUrl = configuredApiUrl && configuredApiUrl.length > 0
  ? configuredApiUrl
  : 'http://localhost:5000/api';

axios.defaults.baseURL = apiBaseUrl.replace(/\/$/, '');

axios.interceptors.request.use(
  (config: InternalAxiosRequestConfig) => {
    const token = localStorage.getItem(JWT_TOKEN_STORAGE_KEY);

    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    } else {
      delete config.headers.Authorization;
    }

    delete config.headers['X-User-ID'];
    return config;
  },
  (error: unknown) => Promise.reject(error)
);

export default axios;
