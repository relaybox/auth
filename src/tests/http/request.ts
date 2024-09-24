interface HTTPResponse {
  statusCode: number;
  error?: string;
  message: Record<string, string> | string;
}

export async function request(
  url: string,
  method: string = 'GET',
  body?: any
): Promise<HTTPResponse> {
  const response = await fetch(url, {
    method,
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(body)
  });

  return response.json() as unknown as HTTPResponse;
}
