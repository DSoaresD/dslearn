package com.devsuperior.dslearnbds.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.devsuperior.dslearnbds.entities.Offer;

@Repository
public interface OfferRepositoy extends JpaRepository<Offer, Long> {

}