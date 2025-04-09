;; Multi-Signature Crypto Treasury
;; Version 1.0: Organizational treasury with multi-signature security
;; This contract implements a crypto treasury with multi-signature approval capabilities.
;; The treasury allows designating "signers" who can collectively authorize transactions if the admin is unavailable.

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
(define-constant ERR_SIGNER_ALREADY_EXISTS (err u103))
(define-constant ERR_SIGNER_DOESNT_EXIST (err u104))
(define-constant ERR_PROPOSAL_IN_PROGRESS (err u105))
(define-constant ERR_NO_PROPOSAL_EXISTS (err u106))
(define-constant ERR_ALREADY_APPROVED (err u107))
(define-constant ERR_INSUFFICIENT_APPROVALS (err u108))
(define-constant ERR_PROPOSAL_EXPIRED (err u109))
(define-constant ERR_INSUFFICIENT_FUNDS (err u110))
(define-constant ERR_INVALID_APPROVAL_PERCENTAGE (err u111))
(define-constant ERR_NULL_ADDRESS (err u112))
(define-constant ERR_INVALID_AMOUNT (err u113))
(define-constant ERR_INVALID_TOKEN (err u114))

;; Data variables

;; Admin of the treasury
(define-data-var admin principal tx-sender)

;; Whether the treasury has been set up
(define-data-var is-setup bool false)

;; List of authorized signers
(define-map signers principal bool)

;; Total number of signers
(define-data-var signer-count uint u0)

;; Approval percentage required for transactions (percentage 1-100)
(define-data-var approval-percentage uint u51)

;; Proposal state
(define-data-var proposal-active bool false)
(define-data-var proposal-creator (optional principal) none)
(define-data-var proposal-beneficiary (optional principal) none)
(define-data-var proposal-deadline uint u0)
(define-map proposal-approvals principal bool)
(define-data-var approval-count uint u0)

;; Constants
(define-constant SECONDS_IN_DAY u86400)
(define-constant PROPOSAL_VALIDITY_DAYS u3)
(define-constant NULL_ADDRESS 'SP000000000000000000002Q6VF78)

;; Read-only functions

;; Check if caller is the admin
(define-read-only (is-admin)
  (is-eq tx-sender (var-get admin)))

;; Check if caller is an authorized signer
(define-read-only (is-signer (signer principal))
  (default-to false (map-get? signers signer)))

;; Get approval percentage
(define-read-only (get-approval-percentage)
  (var-get approval-percentage))

;; Check if proposal is active
(define-read-only (proposal-status)
  {
    active: (var-get proposal-active),
    created-by: (var-get proposal-creator),
    beneficiary: (var-get proposal-beneficiary),
    deadline: (var-get proposal-deadline),
    current-approvals: (var-get approval-count),
    required-approvals: (calculate-required-approvals)
  })

;; Calculate required number of approvals based on percentage
(define-read-only (calculate-required-approvals)
  (let 
    (
      (total-signers (var-get signer-count))
      (percentage (var-get approval-percentage))
    )
    (if (is-eq total-signers u0)
      u0
      (let
        (
          (required-raw (/ (* total-signers percentage) u100))
          ;; Round up if there's a remainder
          (has-remainder (> (* required-raw u100) (* total-signers percentage)))
        )
        (if has-remainder
          (+ required-raw u1)
          required-raw
        )
      )
    )
  ))

;; Get the number of all signers
(define-read-only (get-signer-count)
  (ok (var-get signer-count)))

;; Check if a signer has approved a proposal
(define-read-only (has-approved (signer principal))
  (default-to false (map-get? proposal-approvals signer)))

;; Public functions

;; Set up the treasury
(define-public (setup (new-admin principal) (initial-percentage uint))
  (begin
    ;; Check if already set up
    (asserts! (not (var-get is-setup)) ERR_ALREADY_SETUP)
    
    ;; Validate percentage
    (asserts! (and (>= initial-percentage u1) (<= initial-percentage u100)) ERR_INVALID_APPROVAL_PERCENTAGE)
    
    ;; Validate admin address
    (asserts! (not (is-eq new-admin NULL_ADDRESS)) ERR_NULL_ADDRESS)
    
    ;; Set admin and mark as set up
    (var-set admin new-admin)
    (var-set approval-percentage initial-percentage)
    (var-set is-setup true)
    
    (ok true)))

;; Add a signer - only admin can add signers
(define-public (add-signer (signer principal))
  (begin
    ;; Check if contract is set up
    (asserts! (var-get is-setup) ERR_NOT_SETUP)
    
    ;; Only admin can add signers
    (asserts! (is-admin) ERR_NOT_AUTHORIZED)
    
    ;; Validate signer address
    (asserts! (not (is-eq signer NULL_ADDRESS)) ERR_NULL_ADDRESS)
    
    ;; Check if signer already exists
    (asserts! (not (is-signer signer)) ERR_SIGNER_ALREADY_EXISTS)
    
    ;; Add signer and increment count
    (map-set signers signer true)
    (var-set signer-count (+ (var-get signer-count) u1))
    
    (ok true)))

;; Remove a signer - only admin can remove signers
(define-public (remove-signer (signer principal))
  (begin
    ;; Check if contract is set up
    (asserts! (var-get is-setup) ERR_NOT_SETUP)
    
    ;; Only admin can remove signers
    (asserts! (is-admin) ERR_NOT_AUTHORIZED)
    
    ;; Check that no proposal is active
    (asserts! (not (var-get proposal-active)) ERR_PROPOSAL_IN_PROGRESS)
    
    ;; Check if signer exists
    (asserts! (is-signer signer) ERR_SIGNER_DOESNT_EXIST)
    
    ;; Remove signer and decrement count
    (map-delete signers signer)
    (var-set signer-count (- (var-get signer-count) u1))
    
    (ok true)))

;; Change approval percentage - only admin can change
(define-public (set-approval-percentage (new-percentage uint))
  (begin
    ;; Check if contract is set up
    (asserts! (var-get is-setup) ERR_NOT_SETUP)
    
    ;; Only admin can change percentage
    (asserts! (is-admin) ERR_NOT_AUTHORIZED)
    
    ;; Validate percentage
    (asserts! (and (>= new-percentage u1) (<= new-percentage u100)) ERR_INVALID_APPROVAL_PERCENTAGE)
    
    ;; Set new percentage
    (var-set approval-percentage new-percentage)
    
    (ok true)))

;; Create a new proposal - only signers can create
(define-public (create-proposal (beneficiary principal))
  (begin
    ;; Check if contract is set up
    (asserts! (var-get is-setup) ERR_NOT_SETUP)
    
    ;; Only signers can create proposals
    (asserts! (is-signer tx-sender) ERR_NOT_AUTHORIZED)
    
    ;; Check that no proposal is active
    (asserts! (not (var-get proposal-active)) ERR_PROPOSAL_IN_PROGRESS)
    
    ;; Validate beneficiary address
    (asserts! (not (is-eq beneficiary NULL_ADDRESS)) ERR_NULL_ADDRESS)
    
    ;; Set proposal state
    (var-set proposal-active true)
    (var-set proposal-creator (some tx-sender))
    (var-set proposal-beneficiary (some beneficiary))
    (var-set proposal-deadline (+ burn-block-height (* PROPOSAL_VALIDITY_DAYS SECONDS_IN_DAY)))
    
    ;; Clear previous approvals
    (var-set approval-count u0)
    
    ;; Add first approval
    (map-set proposal-approvals tx-sender true)
    (var-set approval-count (+ (var-get approval-count) u1))
    
    (ok true)))

;; Approve a proposal - only signers can approve
(define-public (approve-proposal)
  (begin
    ;; Check if contract is set up
    (asserts! (var-get is-setup) ERR_NOT_SETUP)
    
    ;; Only signers can approve proposals
    (asserts! (is-signer tx-sender) ERR_NOT_AUTHORIZED)
    
    ;; Check that a proposal is active
    (asserts! (var-get proposal-active) ERR_NO_PROPOSAL_EXISTS)
    
    ;; Check if signer already approved
    (asserts! (not (has-approved tx-sender)) ERR_ALREADY_APPROVED)
    
    ;; Check if proposal period is still valid
    (asserts! (<= burn-block-height (var-get proposal-deadline)) ERR_PROPOSAL_EXPIRED)
    
    ;; Add approval
    (map-set proposal-approvals tx-sender true)
    (var-set approval-count (+ (var-get approval-count) u1))
    
    (ok true)))

;; Execute proposal if threshold is met
(define-public (execute-proposal)
  (begin
    ;; Check if contract is set up
    (asserts! (var-get is-setup) ERR_NOT_SETUP)
    
    ;; Check that a proposal is active
    (asserts! (var-get proposal-active) ERR_NO_PROPOSAL_EXISTS)
    
    ;; Check if proposal period is still valid
    (asserts! (<= burn-block-height (var-get proposal-deadline)) ERR_PROPOSAL_EXPIRED)
    
    ;; Check if enough approvals
    (asserts! (>= (var-get approval-count) (calculate-required-approvals)) ERR_INSUFFICIENT_APPROVALS)
    
    ;; Get the proposed beneficiary and validate
    (let ((beneficiary (unwrap! (var-get proposal-beneficiary) ERR_NOT_SETUP)))
      ;; Double-check the beneficiary is valid (extra safety)
      (asserts! (not (is-eq beneficiary NULL_ADDRESS)) ERR_NULL_ADDRESS)
      
      ;; Update admin
      (var-set admin beneficiary)
      
      ;; Reset proposal state
      (var-set proposal-active false)
      (var-set proposal-creator none)
      (var-set proposal-beneficiary none)
      (var-set approval-count u0)
    )
    
    (ok true)))

;; Cancel proposal - only admin can cancel
(define-public (cancel-proposal)
  (begin
    ;; Check if contract is set up
    (asserts! (var-get is-setup) ERR_NOT_SETUP)
    
    ;; Only admin can cancel proposals
    (asserts! (is-admin) ERR_NOT_AUTHORIZED)
    
    ;; Check that a proposal is active
    (asserts! (var-get proposal-active) ERR_NO_PROPOSAL_EXISTS)
    
    ;; Reset proposal state
    (var-set proposal-active false)
    (var-set proposal-creator none)
    (var-set proposal-beneficiary none)
    (var-set approval-count u0)
    
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

;; Get current admin
(define-read-only (get-admin)
  (ok (var-get admin)))