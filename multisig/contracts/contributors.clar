;; Multi-Signature Crypto Treasury
;; Version 1.0: Basic organizational treasury with admin controls
;; This contract implements a simple crypto treasury with admin management.

;; Define fungible token trait
(define-trait ft-trait
  (
    ;; Transfer from the caller to a new principal
    (transfer (uint principal principal (optional (buff 34))) (response bool uint))
    ;; Get the token balance of the specified principal
    (get-balance (principal) (response uint uint))
  )
)

;; Error codes
(define-constant ERR_NOT_AUTHORIZED (err u100))
(define-constant ERR_ALREADY_SETUP (err u101))
(define-constant ERR_NOT_SETUP (err u102))
(define-constant ERR_NULL_ADDRESS (err u112))
(define-constant ERR_INVALID_AMOUNT (err u113))
(define-constant ERR_INSUFFICIENT_FUNDS (err u110))

;; Data variables

;; Admin of the treasury
(define-data-var admin principal tx-sender)

;; Whether the treasury has been set up
(define-data-var is-setup bool false)

;; Constants
(define-constant NULL_ADDRESS 'SP000000000000000000002Q6VF78)

;; Read-only functions

;; Check if caller is the admin
(define-read-only (is-admin)
  (is-eq tx-sender (var-get admin)))

;; Get current admin
(define-read-only (get-admin)
  (ok (var-get admin)))

;; Public functions

;; Set up the treasury
(define-public (setup (new-admin principal))
  (begin
    ;; Check if already set up
    (asserts! (not (var-get is-setup)) ERR_ALREADY_SETUP)
    
    ;; Validate admin address
    (asserts! (not (is-eq new-admin NULL_ADDRESS)) ERR_NULL_ADDRESS)
    
    ;; Set admin and mark as set up
    (var-set admin new-admin)
    (var-set is-setup true)
    
    (ok true)))

;; Transfer admin rights to another address - only admin can transfer
(define-public (transfer-admin (new-admin principal))
  (begin
    ;; Check if contract is set up
    (asserts! (var-get is-setup) ERR_NOT_SETUP)
    
    ;; Only admin can transfer admin rights
    (asserts! (is-admin) ERR_NOT_AUTHORIZED)
    
    ;; Validate new admin address
    (asserts! (not (is-eq new-admin NULL_ADDRESS)) ERR_NULL_ADDRESS)
    
    ;; Update admin
    (var-set admin new-admin)
    
    (ok true)))

;; Transfer tokens to another address - only admin can transfer
(define-public (send-tokens (token <ft-trait>) (recipient principal) (amount uint))
  (begin
    ;; Check if contract is set up
    (asserts! (var-get is-setup) ERR_NOT_SETUP)
    
    ;; Only admin can transfer
    (asserts! (is-admin) ERR_NOT_AUTHORIZED)
    
    ;; Validate recipient and amount
    (asserts! (not (is-eq recipient NULL_ADDRESS)) ERR_NULL_ADDRESS)
    (asserts! (> amount u0) ERR_INVALID_AMOUNT)
    
    ;; Transfer tokens
    (contract-call? token transfer amount tx-sender recipient none)
  ))

;; Transfer STX to another address - only admin can transfer
(define-public (send-stx (recipient principal) (amount uint))
  (begin
    ;; Check if contract is set up
    (asserts! (var-get is-setup) ERR_NOT_SETUP)
    
    ;; Only admin can transfer
    (asserts! (is-admin) ERR_NOT_AUTHORIZED)
    
    ;; Validate recipient and amount
    (asserts! (not (is-eq recipient NULL_ADDRESS)) ERR_NULL_ADDRESS)
    (asserts! (> amount u0) ERR_INVALID_AMOUNT)
    
    ;; Check if enough balance
    (asserts! (>= (stx-get-balance tx-sender) amount) ERR_INSUFFICIENT_FUNDS)
    
    ;; Transfer STX
    (stx-transfer? amount tx-sender recipient)
  ))