# Exemplo VIDaaS

Aplicação PHP local para testar, com credenciais reais, autorização por QR Code ou push, descoberta do certificado em nuvem e assinatura de um PDF.

O exemplo exige uma aplicação cadastrada no VIDaaS. Configure o mesmo endereço de callback no cadastro do cliente e na variável `VIDAAS_REDIRECT_URI`.

```bash
docker compose build app
docker compose run --rm app composer install

export VIDAAS_CLIENT_ID='...'
export VIDAAS_CLIENT_SECRET='...'
export VIDAAS_BASE_URL='https://hml-certificado.vidaas.com.br'
export VIDAAS_REDIRECT_URI='http://127.0.0.1:8080/'

docker compose run --rm \
  -p 8080:8080 \
  -e VIDAAS_CLIENT_ID \
  -e VIDAAS_CLIENT_SECRET \
  -e VIDAAS_BASE_URL \
  -e VIDAAS_REDIRECT_URI \
  app php -S 0.0.0.0:8080 -t examples/providers/vidaas
```

Nenhuma instalação local de PHP ou Composer é necessária. Abra `http://127.0.0.1:8080/` depois que o servidor indicar que foi iniciado. Use a URL de produção em `VIDAAS_BASE_URL` somente com credenciais de produção.

Credenciais, tokens e documentos permanecem fora do repositório. O token fica apenas na sessão PHP local e o PDF enviado é processado na própria requisição. Este código demonstra a integração e não deve ser publicado como aplicação de produção.
