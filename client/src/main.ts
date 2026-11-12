const status = document.querySelector<HTMLParagraphElement>('#api-status');

if (status) {
  fetch('/api/health')
    .then((response) => {
      if (!response.ok) throw new Error('API unavailable');
      return response.json() as Promise<{ status: string }>;
    })
    .then(({ status: health }) => {
      status.textContent = health === 'ok' ? 'API disponible' : 'API indisponible';
    })
    .catch(() => {
      status.textContent = 'API indisponible';
    });
}
