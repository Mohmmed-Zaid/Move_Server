package com.moveapp.movebackend.model.entities;

import com.moveapp.movebackend.model.enums.RouteType;
import com.moveapp.movebackend.model.enums.TrafficCondition;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

@Entity
@Table(name = "routes")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EntityListeners(AuditingEntityListener.class)
public class Route {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "from_address", nullable = false, length = 500)
    private String fromAddress;

    @Column(name = "to_address", nullable = false, length = 500)
    private String toAddress;

    @Column(name = "from_latitude", nullable = false)
    private Double fromLatitude;

    @Column(name = "from_longitude", nullable = false)
    private Double fromLongitude;

    @Column(name = "to_latitude", nullable = false)
    private Double toLatitude;

    @Column(name = "to_longitude", nullable = false) // Fixed: was toLongitude in entity but to_longitude in DB
    private Double toLongitude;

    @Column(nullable = false)
    private Double distance;

    @Column(nullable = false)
    private Double duration;
    @Enumerated(EnumType.STRING)
    @Column(name = "route_type", nullable = false)
    @Builder.Default
    private RouteType routeType = RouteType.DRIVING;

    @Column(name = "is_favorite", nullable = false)
    @Builder.Default
    private Boolean isFavorite = false;

    @Enumerated(EnumType.STRING)
    @Column(name = "traffic_condition")
    private TrafficCondition trafficCondition;

    @Column(name = "route_coordinates", columnDefinition = "TEXT")
    private String routeCoordinates; // JSON string of route coordinates

    @Column(name = "route_instructions", columnDefinition = "TEXT")
    private String routeInstructions; // JSON string of turn-by-turn instructions

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
}