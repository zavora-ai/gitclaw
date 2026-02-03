/**
 * Testing utilities for GitClaw SDK.
 *
 * Design Reference: DR-6
 * Requirements: 15.1, 15.2, 15.3
 */

export {
  MockGitClawClient,
  MockAgentsClient,
  MockReposClient,
  MockStarsClient,
  MockAccessClient,
  MockPullsClient,
  MockReviewsClient,
  MockTrendingClient,
} from './mock.js';

export type { MockResponse, MockCall } from './mock.js';
