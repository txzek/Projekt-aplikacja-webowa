<?php
declare(strict_types=1);

require dirname(__DIR__) . DIRECTORY_SEPARATOR . 'app' . DIRECTORY_SEPARATOR . 'bootstrap.php';

$userId = isset($_SESSION['user_id']) && is_int($_SESSION['user_id']) ? $_SESSION['user_id'] : null;
$user = null;
if ($userId !== null) {
    $statement = $db->prepare('SELECT id, name, email FROM users WHERE id = :id');
    $statement->execute(['id' => $userId]);
    $user = $statement->fetch();
    if (!$user) {
        unset($_SESSION['user_id']);
        $userId = null;
    }
}

$error = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verifyCsrfToken()) {
        http_response_code(400);
        $error = 'Formularz wygasł lub jest nieprawidłowy. Odśwież stronę i spróbuj ponownie.';
    } else {
        $action = $_POST['action'] ?? '';

        if ($action === 'register' && $userId === null) {
            $name = trim(postString('name'));
            $email = strtolower(trim(postString('email')));
            $password = postString('password');

            if ($name === '' || mb_strlen($name) > 80) {
                $error = 'Imię i nazwisko są wymagane (maksymalnie 80 znaków).';
            } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 254) {
                $error = 'Podaj prawidłowy adres e-mail.';
            } elseif (strlen($password) < 10 || strlen($password) > 72) {
                $error = 'Hasło musi mieć od 10 do 72 znaków.';
            } else {
                $statement = $db->prepare('SELECT id FROM users WHERE email = :email');
                $statement->execute(['email' => $email]);
                if ($statement->fetch()) {
                    $error = 'Konto z tym adresem e-mail już istnieje.';
                } else {
                    $statement = $db->prepare(
                        'INSERT INTO users (name, email, password_hash) VALUES (:name, :email, :password_hash)'
                    );
                    $statement->execute([
                        'name' => $name,
                        'email' => $email,
                        'password_hash' => password_hash($password, PASSWORD_DEFAULT),
                    ]);
                    session_regenerate_id(true);
                    $_SESSION['user_id'] = (int) $db->lastInsertId();
                    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                    setFlash('Konto utworzone. Witaj w Menedżerze wydatków!');
                    redirect();
                }
            }
        } elseif ($action === 'login' && $userId === null) {
            $email = strtolower(trim(postString('email')));
            $password = postString('password');
            $statement = $db->prepare('SELECT id, password_hash FROM users WHERE email = :email');
            $statement->execute(['email' => $email]);
            $account = $statement->fetch();

            if (!$account || !password_verify($password, $account['password_hash'])) {
                $error = 'Nieprawidłowy e-mail lub hasło.';
            } else {
                session_regenerate_id(true);
                $_SESSION['user_id'] = (int) $account['id'];
                $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                setFlash('Zalogowano pomyślnie.');
                redirect();
            }
        } elseif ($action === 'logout' && $userId !== null) {
            $_SESSION = [];
            session_regenerate_id(true);
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            setFlash('Wylogowano.');
            redirect();
        } elseif ($action === 'add_expense' && $userId !== null) {
            $description = trim(postString('description'));
            $amount = trim(postString('amount'));
            $spentOn = trim(postString('spent_on'));

            if ($description === '' || mb_strlen($description) > 200) {
                $error = 'Opis jest wymagany i może mieć maksymalnie 200 znaków.';
            } elseif (!preg_match('/^\d{1,8}(?:[.,]\d{1,2})?$/D', $amount)) {
                $error = 'Podaj kwotę większą od 0, maksymalnie 99 999 999,99.';
            } elseif (!preg_match('/^\d{4}-\d{2}-\d{2}$/D', $spentOn)
                || !checkdate((int) substr($spentOn, 5, 2), (int) substr($spentOn, 8, 2), (int) substr($spentOn, 0, 4))) {
                $error = 'Podaj prawidłową datę wydatku.';
            } else {
                $normalizedAmount = str_replace(',', '.', $amount);
                [$whole, $fraction] = array_pad(explode('.', $normalizedAmount, 2), 2, '0');
                $amountCents = ((int) $whole * 100) + (int) str_pad($fraction, 2, '0');
                if ($amountCents < 1) {
                    $error = 'Kwota musi być większa od 0.';
                } else {
                    $statement = $db->prepare(
                        'INSERT INTO expenses (user_id, description, amount_cents, spent_on)
                         VALUES (:user_id, :description, :amount_cents, :spent_on)'
                    );
                    $statement->execute([
                        'user_id' => $userId,
                        'description' => $description,
                        'amount_cents' => $amountCents,
                        'spent_on' => $spentOn,
                    ]);
                    setFlash('Wydatek został dodany.');
                    redirect();
                }
            }
        } elseif ($action === 'delete_expense' && $userId !== null) {
            $expenseId = filter_var($_POST['expense_id'] ?? null, FILTER_VALIDATE_INT);
            if (!$expenseId || $expenseId < 1) {
                $error = 'Nieprawidłowy wydatek.';
            } else {
                $statement = $db->prepare('DELETE FROM expenses WHERE id = :id AND user_id = :user_id');
                $statement->execute(['id' => $expenseId, 'user_id' => $userId]);
                if ($statement->rowCount() === 0) {
                    $error = 'Nie znaleziono tego wydatku.';
                } else {
                    setFlash('Wydatek został usunięty.');
                    redirect();
                }
            }
        } else {
            http_response_code(400);
            $error = 'Nieprawidłowe żądanie.';
        }
    }
}

$flash = $_SESSION['flash'] ?? null;
unset($_SESSION['flash']);
$expenses = [];
$totalCents = 0;
if ($userId !== null) {
    $statement = $db->prepare(
        'SELECT id, description, amount_cents, spent_on FROM expenses
         WHERE user_id = :user_id ORDER BY spent_on DESC, id DESC'
    );
    $statement->execute(['user_id' => $userId]);
    $expenses = $statement->fetchAll();
    foreach ($expenses as $expense) {
        $totalCents += (int) $expense['amount_cents'];
    }
}
$userInitial = $user ? mb_strtoupper(mb_substr($user['name'], 0, 1)) : '';
?>
<!doctype html>
<html lang="pl">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Menedżer wydatków firmy</title>
    <meta name="theme-color" content="#f5f6f2">
    <link rel="stylesheet" href="style.css">
</head>
<body>
<?php if (!$user): ?>
    <header class="site-header">
        <a class="brand" href="index.php" aria-label="Saldo — strona główna">
            <span class="brand-mark" aria-hidden="true">
                <svg viewBox="0 0 24 24" fill="none"><path d="M4 17.5 9.2 12l3.7 3.7L20 7.5M14.5 7.5H20V13" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
            </span>
            <span>saldo<span class="brand-period">.</span></span>
        </a>
        <span class="header-note"><span class="status-dot"></span> Twoje finanse, tylko dla Ciebie</span>
    </header>

    <main class="auth-page">
        <?php if ($error !== null): ?>
            <div class="notice notice-error" role="alert">
                <span class="notice-icon" aria-hidden="true">!</span>
                <span><?= h($error) ?></span>
            </div>
        <?php endif; ?>
        <?php if (is_array($flash)): ?>
            <div class="notice notice-<?= h($flash['type']) ?>" role="status"><?= h($flash['message']) ?></div>
        <?php endif; ?>

        <div class="auth-layout">
            <section class="welcome-panel">
                <div class="welcome-copy">
                    <p class="eyebrow eyebrow-light"><span class="eyebrow-line"></span> MĄDRZEJ O PIENIĄDZACH</p>
                    <h1>Każdy wydatek<br>ma swoje <span>miejsce.</span></h1>
                    <p class="welcome-description">Porządek w firmowych wydatkach zaczyna się od prostych decyzji. Zapisuj koszty, wracaj do nich, kiedy potrzebujesz.</p>
                    <div class="welcome-points">
                        <div class="welcome-point">
                            <span class="point-icon" aria-hidden="true">
                                <svg viewBox="0 0 24 24" fill="none"><path d="M5 12.5 9.2 17 19 7" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
                            </span>
                            Wszystkie wydatki w jednym miejscu
                        </div>
                        <div class="welcome-point">
                            <span class="point-icon" aria-hidden="true">
                                <svg viewBox="0 0 24 24" fill="none"><path d="M12 3 19 6v5c0 4.5-2.8 7.6-7 10-4.2-2.4-7-5.5-7-10V6l7-3Z" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/><path d="m9 12 2 2 4-4" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>
                            Twoje konto. Twoje dane.
                        </div>
                    </div>
                </div>
                <div class="welcome-visual" aria-hidden="true">
                    <div class="visual-orbit orbit-one"></div>
                    <div class="visual-orbit orbit-two"></div>
                    <div class="visual-card">
                        <div class="visual-card-top">
                            <span class="visual-card-label"><span class="visual-card-icon">↗</span> DOBRY KIERUNEK</span>
                            <span class="visual-card-dots">•••</span>
                        </div>
                        <div class="visual-card-title">Świadome wydatki</div>
                        <div class="visual-card-subtitle">zaczynają się od dobrego przeglądu</div>
                        <div class="chart-lines"><i></i><i></i><i></i><i></i></div>
                        <div class="chart-bars"><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i></div>
                        <div class="chart-months"><span>STY</span><span>MAR</span><span>MAJ</span><span>LIP</span><span>WRZ</span><span>LIS</span></div>
                    </div>
                    <div class="visual-sticker"><span class="sticker-star">✳</span><span>Prościej<br>znaczy lepiej.</span></div>
                </div>
                <div class="welcome-footer"><span>MAŁY KROK DO WIĘKSZEGO PORZĄDKU</span><span>01 — 02</span></div>
            </section>

            <section class="auth-panel" aria-label="Logowanie i rejestracja">
                <div class="auth-heading">
                    <p class="eyebrow">ZACZNIJ TUTAJ</p>
                    <h2>Dobrze Cię widzieć.</h2>
                    <p>Zaloguj się lub utwórz konto, żeby przejść do swoich wydatków.</p>
                </div>

                <div class="auth-cards">
                    <section class="auth-card">
                        <div class="card-heading">
                            <span class="card-icon" aria-hidden="true">
                                <svg viewBox="0 0 24 24" fill="none"><path d="M15 20v-1.8a3.2 3.2 0 0 0-3.2-3.2H7.2A3.2 3.2 0 0 0 4 18.2V20m11-13.5a3.2 3.2 0 0 1 0 6.1m5 7.4v-1.8a3.2 3.2 0 0 0-2.4-3.1M9.5 11.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7Z" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>
                            </span>
                            <span class="card-kicker">MASZ JUŻ KONTO?</span>
                        </div>
                        <h3>Wróć do swoich spraw.</h3>
                        <form method="post" class="form-stack">
                            <input type="hidden" name="csrf_token" value="<?= h(csrfToken()) ?>">
                            <input type="hidden" name="action" value="login">
                            <div class="field">
                                <label for="login-email">Adres e-mail</label>
                                <input id="login-email" name="email" type="email" maxlength="254" autocomplete="email" placeholder="ty@firma.pl" required>
                            </div>
                            <div class="field">
                                <label for="login-password">Hasło</label>
                                <input id="login-password" name="password" type="password" autocomplete="current-password" placeholder="Wpisz swoje hasło" required>
                            </div>
                            <button class="button button-dark" type="submit">Zaloguj się <span aria-hidden="true">↗</span></button>
                        </form>
                    </section>

                    <section class="auth-card register-card">
                        <div class="card-heading">
                            <span class="card-icon card-icon-warm" aria-hidden="true">
                                <svg viewBox="0 0 24 24" fill="none"><path d="M12 5v14M5 12h14" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>
                            </span>
                            <span class="card-kicker">PIERWSZY RAZ?</span>
                        </div>
                        <h3>Zacznij od nowa.</h3>
                        <form method="post" class="form-stack">
                            <input type="hidden" name="csrf_token" value="<?= h(csrfToken()) ?>">
                            <input type="hidden" name="action" value="register">
                            <div class="field">
                                <label for="register-name">Imię i nazwisko</label>
                                <input id="register-name" name="name" type="text" maxlength="80" autocomplete="name" placeholder="Jak się do Ciebie zwracać?" required>
                            </div>
                            <div class="field">
                                <label for="register-email">Adres e-mail</label>
                                <input id="register-email" name="email" type="email" maxlength="254" autocomplete="email" placeholder="ty@firma.pl" required>
                            </div>
                            <div class="field">
                                <label for="register-password">Hasło <span class="label-hint">min. 10 znaków</span></label>
                                <input id="register-password" name="password" type="password" minlength="10" maxlength="72" autocomplete="new-password" placeholder="Wymyśl bezpieczne hasło" required>
                            </div>
                            <button class="button button-green" type="submit">Utwórz bezpłatne konto <span aria-hidden="true">↗</span></button>
                        </form>
                    </section>
                </div>
                <p class="auth-privacy"><span aria-hidden="true">⌑</span> Twoje hasło jest bezpiecznie szyfrowane i nie jest nikomu udostępniane.</p>
            </section>
        </div>
    </main>
    <footer class="site-footer"><span>© <?= date('Y') ?> SALDO</span><span>ZROBIONE Z MYŚLĄ O SPOKOJU.</span></footer>
<?php else: ?>
    <header class="site-header dashboard-header">
        <a class="brand" href="index.php" aria-label="Saldo — strona główna">
            <span class="brand-mark" aria-hidden="true">
                <svg viewBox="0 0 24 24" fill="none"><path d="M4 17.5 9.2 12l3.7 3.7L20 7.5M14.5 7.5H20V13" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
            </span>
            <span>saldo<span class="brand-period">.</span></span>
        </a>
        <div class="dashboard-top-right">
            <span class="workspace-label"><span class="status-dot"></span> TWOJA PRZESTRZEŃ</span>
            <div class="user-chip">
                <span class="user-avatar"><?= h($userInitial) ?></span>
                <span class="user-name"><?= h($user['name']) ?></span>
            </div>
            <form method="post" class="logout-form">
                <input type="hidden" name="csrf_token" value="<?= h(csrfToken()) ?>">
                <input type="hidden" name="action" value="logout">
                <button class="logout-button" type="submit" aria-label="Wyloguj się" title="Wyloguj się">
                    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M10 17l5-5-5-5m5 5H3m9-9h6a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-6" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>
                    <span>Wyloguj</span>
                </button>
            </form>
        </div>
    </header>

    <main class="dashboard-page">
        <?php if ($error !== null): ?>
            <div class="notice notice-error" role="alert">
                <span class="notice-icon" aria-hidden="true">!</span>
                <span><?= h($error) ?></span>
            </div>
        <?php endif; ?>
        <?php if (is_array($flash)): ?>
            <div class="notice notice-<?= h($flash['type']) ?>" role="status"><?= h($flash['message']) ?></div>
        <?php endif; ?>

        <section class="dashboard-welcome">
            <div>
                <p class="eyebrow"><span class="eyebrow-line"></span> PRZEGLĄD WYDATKÓW</p>
                <h1>Dzień dobry, <?= h($user['name']) ?> <span class="greeting-mark">✳</span></h1>
                <p>Spokojnie. Wszystko, co ważne, masz teraz w jednym miejscu.</p>
            </div>
            <div class="today-date">
                <span class="today-date-icon" aria-hidden="true">
                    <svg viewBox="0 0 24 24" fill="none"><rect x="3.5" y="5" width="17" height="16" rx="2.5" stroke="currentColor" stroke-width="1.6"/><path d="M7.5 3v4M16.5 3v4M3.5 10h17" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>
                </span>
                <span><span class="today-date-label">DZISIAJ</span><strong><?= h(date('d.m.Y')) ?></strong></span>
            </div>
        </section>

        <section class="stats-grid" aria-label="Podsumowanie wydatków">
            <article class="stat-card stat-card-total">
                <div class="stat-topline"><span>SUMA TWOICH WYDATKÓW</span><span class="stat-icon" aria-hidden="true">↗</span></div>
                <strong><?= number_format($totalCents / 100, 2, ',', ' ') ?><span> zł</span></strong>
                <div class="stat-foot"><span class="stat-indicator"></span> Łączna wartość dodanych pozycji</div>
                <div class="stat-decoration" aria-hidden="true"><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i></div>
            </article>
            <article class="stat-card stat-card-count">
                <div class="stat-topline"><span>ZAPISANE POZYCJE</span><span class="count-icon" aria-hidden="true">
                    <svg viewBox="0 0 24 24" fill="none"><path d="M7 4h10a2 2 0 0 1 2 2v14l-7-3.5L5 20V6a2 2 0 0 1 2-2Z" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/><path d="M9 8h6M9 11h6" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
                </span></div>
                <strong><?= count($expenses) ?><span> <?= count($expenses) === 1 ? 'wydatek' : (count($expenses) >= 2 && count($expenses) <= 4 ? 'wydatki' : 'wydatków') ?></span></strong>
                <div class="stat-foot"><span class="count-dot"></span> <?= $expenses ? 'Każdy z nich jest pod Twoją kontrolą' : 'Twoja historia dopiero się zaczyna' ?></div>
            </article>
        </section>

        <div class="dashboard-grid">
            <section class="expenses-section">
                <div class="section-heading">
                    <div>
                        <p class="eyebrow"><span class="eyebrow-line"></span> TWOJA HISTORIA</p>
                        <h2>Ostatnie wydatki</h2>
                    </div>
                    <span class="item-count"><?= count($expenses) ?> <?= count($expenses) === 1 ? 'pozycja' : 'pozycji' ?></span>
                </div>
                <?php if (!$expenses): ?>
                    <div class="empty-state">
                        <span class="empty-illustration" aria-hidden="true">
                            <svg viewBox="0 0 64 64" fill="none"><rect x="13" y="9" width="35" height="44" rx="6" fill="#EFF3EA" stroke="#D8E1D2" stroke-width="1.5"/><path d="M22 22h17M22 29h17M22 36h9" stroke="#8EAA8F" stroke-width="2" stroke-linecap="round"/><circle cx="45" cy="44" r="10" fill="#E4EFE1" stroke="#CBDCC8" stroke-width="1.5"/><path d="M45 39v10m-3-7h4a2 2 0 1 1 0 4h-4" stroke="#4F7757" stroke-width="1.5" stroke-linecap="round"/></svg>
                        </span>
                        <h3>Tu zacznie się dobry porządek.</h3>
                        <p>Dodaj pierwszy wydatek, a pojawi się tutaj razem z datą i kwotą.</p>
                    </div>
                <?php else: ?>
                    <div class="expense-list">
                        <div class="expense-list-header"><span>OPIS WYDATKU</span><span>DATA</span><span>KWOTA</span><span></span></div>
                        <?php foreach ($expenses as $expense): ?>
                            <article class="expense-row">
                                <span class="expense-type-icon" aria-hidden="true">
                                    <svg viewBox="0 0 24 24" fill="none"><path d="M7 4h10a2 2 0 0 1 2 2v14l-7-3.5L5 20V6a2 2 0 0 1 2-2Z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M9 8h6M9 11h6" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
                                </span>
                                <div class="expense-description">
                                    <h3><?= h($expense['description']) ?></h3>
                                    <span>Wydatek firmowy</span>
                                </div>
                                <time datetime="<?= h($expense['spent_on']) ?>"><?= h(date('d.m.Y', strtotime($expense['spent_on']))) ?></time>
                                <strong class="expense-amount"><?= number_format((int) $expense['amount_cents'] / 100, 2, ',', ' ') ?> zł</strong>
                                <form method="post" class="delete-form">
                                    <input type="hidden" name="csrf_token" value="<?= h(csrfToken()) ?>">
                                    <input type="hidden" name="action" value="delete_expense">
                                    <input type="hidden" name="expense_id" value="<?= (int) $expense['id'] ?>">
                                    <button class="delete-button" type="submit" aria-label="Usuń wydatek: <?= h($expense['description']) ?>" title="Usuń wydatek">
                                        <svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M4 7h16m-10 4v6m4-6v6M6 7l1 13h10l1-13M9 7V4h6v3" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>
                                    </button>
                                </form>
                            </article>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
                <div class="list-note"><span aria-hidden="true">✳</span> <?= $expenses ? 'Twoje wydatki są widoczne tylko dla Ciebie.' : 'Każdy nowy wydatek automatycznie trafi na tę listę.' ?></div>
            </section>

            <aside class="add-card">
                <div class="add-card-heading">
                    <span class="add-card-icon" aria-hidden="true">
                        <svg viewBox="0 0 24 24" fill="none"><path d="M12 5v14M5 12h14" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>
                    </span>
                    <p class="eyebrow"><span class="eyebrow-line"></span> NOWA POZYCJA</p>
                </div>
                <h2>Dodaj wydatek.</h2>
                <p class="add-card-description">Zapisz szczegóły. Resztą zajmie się Twoja lista.</p>
                <form method="post" class="expense-form">
                    <input type="hidden" name="csrf_token" value="<?= h(csrfToken()) ?>">
                    <input type="hidden" name="action" value="add_expense">
                    <div class="field">
                        <label for="description">Za co był wydatek?</label>
                        <input id="description" name="description" type="text" maxlength="200" placeholder="np. Materiały biurowe" required>
                    </div>
                    <div class="field">
                        <label for="amount">Kwota</label>
                        <div class="amount-input">
                            <input id="amount" name="amount" type="number" min="0.01" max="99999999.99" step="0.01" placeholder="0,00" required>
                            <span>PLN</span>
                        </div>
                    </div>
                    <div class="field">
                        <label for="spent-on">Kiedy?</label>
                        <input id="spent-on" name="spent_on" type="date" value="<?= h(date('Y-m-d')) ?>" required>
                    </div>
                    <button class="button button-green add-expense-button" type="submit">
                        Dodaj do listy
                        <svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M5 12h14m-6-6 6 6-6 6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
                    </button>
                </form>
                <div class="secure-note"><span aria-hidden="true">
                    <svg viewBox="0 0 24 24" fill="none"><path d="M12 3 19 6v5c0 4.5-2.8 7.6-7 10-4.2-2.4-7-5.5-7-10V6l7-3Z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="m9 12 2 2 4-4" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>
                </span>Twoje dane są prywatne i bezpieczne.</div>
            </aside>
        </div>
        <footer class="dashboard-footer"><span>SALDO <span class="brand-period">·</span> PORZĄDEK W WYDATKACH</span><span>MIŁEGO DNIA I DOBRYCH DECYZJI.</span></footer>
    </main>
<?php endif; ?>
</body>
</html>
