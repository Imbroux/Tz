CREATE TABLE users
(
    id            SERIAL       NOT NULL UNIQUE,
    login         VARCHAR(255) NOT NULL UNIQUE,
    password_hash TEXT         NOT NULL,
    current_balance NUMERIC DEFAULT 0,
    withdrawn_balance NUMERIC DEFAULT 0
)
CREATE TABLE orders
(
    id           SERIAL PRIMARY KEY,
    login        VARCHAR(255) NOT NULL,
    order_number VARCHAR(255) NOT NULL,
    status       VARCHAR(20)  NOT NULL,
    accrual      INTEGER,
    uploaded_at  TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (login, order_number)
);
CREATE TABLE withdrawals (
                             id SERIAL PRIMARY KEY,
                             login VARCHAR(255) NOT NULL,
                             order_number VARCHAR(255) NOT NULL,
                             amount NUMERIC NOT NULL,
                             created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);



