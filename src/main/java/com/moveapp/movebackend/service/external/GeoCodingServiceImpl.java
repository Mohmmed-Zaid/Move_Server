package com.moveapp.movebackend.service.external;

import com.moveapp.movebackend.model.dto.LocationDto.LocationDto;
import com.moveapp.movebackend.model.entities.Location;
import com.moveapp.movebackend.model.enums.LocationCategory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import com.moveapp.movebackend.service.external.GeoCodingService;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service
@Slf4j
public class GeoCodingServiceImpl implements GeoCodingService {

    @Override
    public List<Location> searchLocations(String query) {
        log.info("Searching for locations with query: {}", query);

        // Mock implementation - in real app, this would call Google Maps API or similar
        List<Location> results = new ArrayList<>();

        // Add some mock results based on common queries
        if (query.toLowerCase().contains("restaurant")) {
            results.add(createMockLocation("Best Restaurant", 40.7128, -74.0060, LocationCategory.RESTAURANT));
            results.add(createMockLocation("Good Eats Cafe", 40.7589, -73.9851, LocationCategory.RESTAURANT));
        } else if (query.toLowerCase().contains("hospital")) {
            results.add(createMockLocation("City General Hospital", 40.7505, -73.9934, LocationCategory.HOSPITAL));
        } else if (query.toLowerCase().contains("school")) {
            results.add(createMockLocation("Central High School", 40.7831, -73.9712, LocationCategory.SCHOOL));
        } else {
            // Generic location
            results.add(createMockLocation(query + " Location", 40.7128, -74.0060, LocationCategory.OTHER));
        }

        return results;
    }

    @Override
    public LocationDto reverseGeocode(double latitude, double longitude) {
        log.info("Reverse geocoding for coordinates: {}, {}", latitude, longitude);

        // Mock implementation
        String address = String.format("Address near %.4f, %.4f", latitude, longitude);

        return LocationDto.builder()
                .address(address)
                .latitude(latitude)
                .longitude(longitude)
                .category(LocationCategory.OTHER)
                .isPopular(false)
                .build();
    }

    @Override
    public LocationDto geocode(String address) {
        log.info("Geocoding address: {}", address);

        // Mock implementation - return coordinates for NYC area
        return LocationDto.builder()
                .address(address)
                .latitude(40.7128 + (Math.random() - 0.5) * 0.1) // Random lat near NYC
                .longitude(-74.0060 + (Math.random() - 0.5) * 0.1) // Random lon near NYC
                .category(LocationCategory.OTHER)
                .isPopular(false)
                .build();
    }

    private Location createMockLocation(String address, double lat, double lon, LocationCategory category) {
        return Location.builder()
                .address(address)
                .latitude(lat)
                .longitude(lon)
                .placeId("mock_" + UUID.randomUUID().toString())
                .category(category)
                .isPopular(false)
                .searchCount(0L)
                .build();
    }
}
