/**
 * Reviews resource client.
 *
 * Design Reference: DR-5
 * Requirements: 9.3
 */

import type { HTTPTransport } from '../transport.js';
import type { Review } from '../types/index.js';

/**
 * Parse ISO date string to Date object.
 */
function parseDate(dateStr: string): Date {
  return new Date(dateStr.replace(/Z$/, '+00:00'));
}

/**
 * Get value from object, trying camelCase first then snake_case.
 */
function getValue<T>(
  data: Record<string, unknown>,
  camel: string,
  snake: string,
  defaultValue?: T
): T {
  if (camel in data) {
    return data[camel] as T;
  }
  return (data[snake] ?? defaultValue) as T;
}

/**
 * Client for pull request review operations.
 *
 * Design Reference: DR-5
 */
export class ReviewsClient {
  private transport: HTTPTransport;

  /**
   * Initialize the reviews client.
   *
   * @param transport - HTTP transport for making requests
   */
  constructor(transport: HTTPTransport) {
    this.transport = transport;
  }

  /**
   * Submit a review for a pull request.
   *
   * The PR author cannot approve their own PR.
   *
   * @param repoId - The repository identifier
   * @param prId - The pull request identifier
   * @param verdict - "approve", "request_changes", or "comment"
   * @param body - Optional review comment
   * @returns Review object with reviewId
   * @throws AuthenticationError if signature is invalid
   * @throws ValidationError if self-approval attempted
   * @throws NotFoundError if pull request not found
   *
   * Requirements: 9.3
   */
  async create(
    repoId: string,
    prId: string,
    verdict: 'approve' | 'request_changes' | 'comment',
    body?: string | null
  ): Promise<Review> {
    const requestBody: Record<string, unknown> = {
      repoId,
      prId,
      verdict,
      body: body ?? null,
    };

    const response = await this.transport.signedRequest(
      'POST',
      `/v1/repos/${repoId}/pulls/${prId}/reviews`,
      'pr_review',
      requestBody
    );

    const data = (response.data ?? {}) as Record<string, unknown>;
    return {
      reviewId: data.reviewId as string,
      prId: data.prId as string,
      reviewerId: data.reviewerId as string,
      verdict: data.verdict as 'approve' | 'request_changes' | 'comment',
      body: (data.body as string | null) ?? null,
      createdAt: parseDate(data.createdAt as string),
    };
  }

  /**
   * List reviews for a pull request.
   *
   * @param repoId - The repository identifier
   * @param prId - The pull request identifier
   * @returns List of Review objects
   * @throws NotFoundError if pull request not found
   *
   * Requirements: 9.3
   */
  async list(repoId: string, prId: string): Promise<Review[]> {
    const response = await this.transport.unsignedRequest(
      'GET',
      `/v1/repos/${repoId}/pulls/${prId}/reviews`
    );

    const data = (response.data ?? {}) as Record<string, unknown>;
    // Handle both list and dict responses
    let reviews: Record<string, unknown>[];
    if (Array.isArray(data)) {
      reviews = data as Record<string, unknown>[];
    } else {
      reviews = (data.reviews ?? []) as Record<string, unknown>[];
    }

    return reviews.map((review) => ({
      reviewId: getValue<string>(review, 'reviewId', 'review_id', ''),
      prId: getValue<string>(review, 'prId', 'pr_id', ''),
      reviewerId: getValue<string>(review, 'reviewerId', 'reviewer_id', ''),
      verdict: review.verdict as 'approve' | 'request_changes' | 'comment',
      body: (review.body as string | null) ?? null,
      createdAt: parseDate(getValue<string>(review, 'createdAt', 'created_at', '')),
    }));
  }
}
