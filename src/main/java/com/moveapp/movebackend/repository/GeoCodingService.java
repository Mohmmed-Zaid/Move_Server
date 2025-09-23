package com.moveapp.movebackend.service.external;

import com.moveapp.movebackend.model.dto.LocationDto.LocationDto;
import com.moveapp.movebackend.model.entities.Location;
import java.util.List;

public interface GeoCodingService {
    List<Location> searchLocations(String query);
    LocationDto reverseGeocode(double latitude, double longitude);
    LocationDto geocode(String address);
}