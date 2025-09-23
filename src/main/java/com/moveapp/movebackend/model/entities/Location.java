package com.moveapp.movebackend.model.entities;

import com.moveapp.movebackend.model.enums.LocationCategory;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

@Entity
@Table(name = "locations")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EntityListeners(AuditingEntityListener.class)
public class Location {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 500)
    private String address;

    @Column(nullable = false)
    private Double latitude;

    @Column(nullable = false)
    private Double longitude;

    @Column(unique = true, length = 100)
    private String placeId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    @Builder.Default
    private LocationCategory category = LocationCategory.OTHER;

    @Column(nullable = false)
    @Builder.Default
    private Boolean isPopular = false;

    @Column(nullable = false)
    @Builder.Default
    private Long searchCount = 0L;

    @CreatedDate
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    private LocalDateTime updatedAt;
}
