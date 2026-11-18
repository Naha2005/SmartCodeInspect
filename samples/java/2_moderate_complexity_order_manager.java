/**
 * Sample 2: Moderate Complexity (Code Smells & Resource Flaws)
 * Language: Java
 * Purpose: Demonstrates long parameter list smell, console logging in production,
 * empty exception handler, and cyclomatic branching debt.
 * Flagged Rules:
 * - SMELL-JV-004 (Long parameter list smell)
 * - SMELL-JV-002 (Console output left in production)
 * - SMELL-JV-001 (Empty catch block / swallowed exception)
 * - COMPLEX-JV-002 (Deeply nested branching logic)
 */

import java.util.*;
import java.io.*;

public class OrderNotificationManager {

    // Quality Smell: Long parameter list (7 parameters)
    public void dispatchOrderAlert(
        long orderId,
        String customerEmail,
        String customerPhone,
        double orderTotal,
        int priorityTier,
        boolean isExpressShipping,
        String destinationRegion
    ) {
        // Quality Smell: Console output left in production
        System.out.println("Dispatching notification for order ID: " + orderId);

        // Quality Smell: Deeply nested conditional logic / high complexity
        if (customerEmail != null && !customerEmail.trim().isEmpty()) {
            if (priorityTier > 3) {
                if (isExpressShipping) {
                    if (orderTotal > 1000.0) {
                        scheduleEmail(customerEmail, "URGENT_HIGH_VALUE");
                    } else {
                        scheduleEmail(customerEmail, "URGENT_STANDARD");
                    }
                } else {
                    scheduleEmail(customerEmail, "STANDARD");
                }
            }
        }

        // Quality Smell: Empty catch block / swallowed exception
        try {
            validateRegionRouting(destinationRegion);
        } catch (Exception e) {
            // Silently swallowed without logging
        }
    }

    private void scheduleEmail(String email, String template) {
        // Internal scheduling logic
    }

    private void validateRegionRouting(String region) throws Exception {
        if (region == null || region.isEmpty()) {
            throw new IllegalArgumentException("Invalid region");
        }
    }
}
