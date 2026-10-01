<?php

declare(strict_types=1);

use SignerPHP\PdfSigner\Infrastructure\Remote\Vidaas\VidaasPkce;
use SignerPHP\PdfSigner\Presentation\Signer;

require __DIR__.'/bootstrap.php';

$error = null;
$message = null;

try {
    $action = $_POST['action'] ?? null;
    if ($action === 'reset') {
        session_destroy();
        redirectHome();
    }

    if ($action === 'start_qr') {
        $verifier = VidaasPkce::generateVerifier();
        $state = bin2hex(random_bytes(16));
        $_SESSION['vidaas_verifier'] = $verifier;
        $_SESSION['vidaas_state'] = $state;
        header('Location: '.authorization()->authorizationUrl(
            VidaasPkce::challenge($verifier),
            redirectUri: callbackUrl(),
            state: $state,
            loginHint: trim((string) ($_POST['login_hint'] ?? '')) ?: null,
        ));
        exit;
    }

    if (isset($_GET['code'])) {
        $state = (string) ($_GET['state'] ?? '');
        if (! hash_equals((string) ($_SESSION['vidaas_state'] ?? ''), $state)) {
            throw new RuntimeException('O state retornado pelo VIDaaS é inválido.');
        }
        $token = authorization()->exchangeAuthorizationCode(
            (string) $_GET['code'],
            (string) ($_SESSION['vidaas_verifier'] ?? ''),
            callbackUrl(),
        );
        $_SESSION['vidaas_access_token'] = $token->value;
        unset($_SESSION['vidaas_state'], $_SESSION['vidaas_verifier']);
        $message = 'Autorização por QR Code concluída.';
    }

    if ($action === 'start_push') {
        $verifier = VidaasPkce::generateVerifier();
        $push = authorization()->startPush(
            VidaasPkce::challenge($verifier),
            trim((string) ($_POST['login_hint'] ?? '')),
        );
        $_SESSION['vidaas_verifier'] = $verifier;
        $_SESSION['vidaas_push_code'] = $push->code;
        $message = 'Notificação enviada. Autorize no aplicativo e clique em verificar.';
    }

    if ($action === 'poll_push') {
        $push = authorization()->pollPush((string) ($_SESSION['vidaas_push_code'] ?? ''));
        if (! $push->approved || $push->authorizationToken === null) {
            $message = 'A autorização ainda está pendente no aplicativo VIDaaS.';
        } else {
            $token = authorization()->exchangeAuthorizationCode(
                $push->authorizationToken,
                (string) ($_SESSION['vidaas_verifier'] ?? ''),
                'push://',
            );
            $_SESSION['vidaas_access_token'] = $token->value;
            unset($_SESSION['vidaas_push_code'], $_SESSION['vidaas_verifier']);
            $message = 'Autorização por push concluída.';
        }
    }

    if ($action === 'sign') {
        $upload = $_FILES['pdf'] ?? null;
        if (! is_array($upload) || ($upload['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
            throw new RuntimeException('Selecione um PDF válido.');
        }
        $pdf = file_get_contents((string) $upload['tmp_name']);
        if (! is_string($pdf) || ! str_starts_with($pdf, '%PDF-')) {
            throw new RuntimeException('O arquivo enviado não é um PDF.');
        }

        $alias = trim((string) ($_POST['certificate_alias'] ?? ''));
        $vidaas = provider();
        $certificate = $vidaas->certificates($alias)[0];
        $builder = Signer::externalSigner()
            ->withPdfContent($pdf)
            ->withCertificate($certificate->pem)
            ->withPadesBaselineB();
        $prepared = $builder->prepare();
        $signature = $vidaas->sign($prepared->payload, $certificate->alias);
        $signedPdf = $builder->complete($prepared->state, $signature->bytes);

        header('Content-Type: application/pdf');
        header('Content-Disposition: attachment; filename="signed-vidaas.pdf"');
        header('Content-Length: '.strlen($signedPdf));
        echo $signedPdf;
        exit;
    }
} catch (Throwable $exception) {
    $error = $exception->getMessage();
}

$certificates = [];
if (isset($_SESSION['vidaas_access_token'])) {
    try {
        $certificates = provider()->certificates();
    } catch (Throwable $exception) {
        $error = $exception->getMessage();
    }
}
?>
<!doctype html>
<html lang="pt-BR">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Exemplo de assinatura VIDaaS</title>
    <style>
        body { background: #f5f6f8; color: #20242c; font: 16px/1.5 system-ui, sans-serif; margin: 0; }
        main { margin: 40px auto; max-width: 760px; padding: 0 20px; }
        section { background: white; border: 1px solid #dfe3e8; border-radius: 12px; margin: 18px 0; padding: 24px; }
        form { display: grid; gap: 12px; } input, select, button { box-sizing: border-box; font: inherit; padding: 10px 12px; }
        button { cursor: pointer; } .notice { background: #e8f5e9; } .error { background: #ffebee; color: #9f1c25; }
        code { overflow-wrap: anywhere; } small { color: #606a78; }
    </style>
</head>
<body><main>
    <h1>Assinatura real com VIDaaS</h1>
    <p>Exemplo local dos fluxos QR Code e push, descoberta do certificado em nuvem e assinatura PAdES.</p>
    <?php if ($message) { ?><section class="notice"><?= escape($message) ?></section><?php } ?>
    <?php if ($error) { ?><section class="error"><?= escape($error) ?></section><?php } ?>

    <?php if (! isset($_SESSION['vidaas_access_token'])) { ?>
        <section><h2>1. Autorizar por QR Code</h2>
            <form method="post"><input type="hidden" name="action" value="start_qr">
                <label>CPF <small>(opcional)</small><input name="login_hint" inputmode="numeric"></label>
                <button>Continuar no VIDaaS</button>
            </form>
        </section>
        <section><h2>Ou autorizar por push</h2>
            <?php if (! isset($_SESSION['vidaas_push_code'])) { ?>
                <form method="post"><input type="hidden" name="action" value="start_push">
                    <label>CPF<input name="login_hint" inputmode="numeric" required></label>
                    <button>Enviar notificação</button>
                </form>
            <?php } else { ?>
                <p>Código da solicitação: <code><?= escape((string) $_SESSION['vidaas_push_code']) ?></code></p>
                <form id="push-poll" method="post"><input type="hidden" name="action" value="poll_push"><button>Verificar aprovação</button></form>
            <?php } ?>
        </section>
    <?php } else { ?>
        <section><h2>2. Selecionar certificado e assinar</h2>
            <form method="post" enctype="multipart/form-data"><input type="hidden" name="action" value="sign">
                <label>Certificado<select name="certificate_alias" required>
                    <?php foreach ($certificates as $certificate) { ?>
                        <option value="<?= escape($certificate->alias) ?>"><?= escape($certificate->alias) ?></option>
                    <?php } ?>
                </select></label>
                <label>Documento PDF<input type="file" name="pdf" accept="application/pdf" required></label>
                <button>Assinar e baixar PDF</button>
            </form>
        </section>
    <?php } ?>
    <form method="post"><input type="hidden" name="action" value="reset"><button>Reiniciar sessão</button></form>
</main>
<?php if (isset($_SESSION['vidaas_push_code']) && ! isset($_SESSION['vidaas_access_token'])) { ?>
<script>window.setTimeout(() => document.querySelector('#push-poll')?.requestSubmit(), 2500)</script>
<?php } ?>
</body></html>
