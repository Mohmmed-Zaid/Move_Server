package com.moveapp.movebackend.utils;

public class ValidationUtils {

    public static boolean isValidCoordinate(double latitude, double longitude) {
        return latitude >= -90.0 && latitude <= 90.0 &&
                longitude >= -180.0 && longitude <= 180.0;
    }

    /**
     * Check if location update is reasonable (not teleporting)
     * @param prevLat Previous latitude
     * @param prevLon Previous longitude
     * @param newLat New latitude
     * @param newLon New longitude
     * @param timeDeltaMs Time difference in milliseconds
     * @return true if update seems reasonable
     */
    public static boolean isReasonableLocationUpdate(double prevLat, double prevLon,
                                                     double newLat, double newLon,
                                                     long timeDeltaMs) {
        if (timeDeltaMs <= 0) return true; // No time passed

        double distance = GeoUtils.calculateHaversineDistance(prevLat, prevLon, newLat, newLon);
        double maxSpeedKmh = 300.0; // Maximum reasonable speed (like a fast train)
        double maxDistanceKm = (maxSpeedKmh * timeDeltaMs) / (1000.0 * 3600.0);

        return distance <= maxDistanceKm;
    }

    public static boolean isValidEmail(String email) {
        return email != null && email.matches("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");
    }

    public static boolean isValidPhoneNumber(String phone) {
        return phone != null && phone.matches("^\\+?[1-9]\\d{1,14}$");
    }
}