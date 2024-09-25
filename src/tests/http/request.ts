interface HTTPResponse<T> {
  status: number;
  data: T;
}

const API_SERVICE_URL = 'http://localhost:40060/dev';

export async function request<T = any>(
  url: string,
  options: RequestInit = {}
): Promise<HTTPResponse<T>> {
  const requestUrl = `${API_SERVICE_URL}${url}`;
  const response = await fetch(requestUrl, options);
  const data = (await response.json()) as unknown as T;

  return {
    status: response.status,
    data
  };
}
