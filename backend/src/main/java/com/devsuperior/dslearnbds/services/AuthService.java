package com.devsuperior.dslearnbds.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.devsuperior.dslearnbds.entities.User;
import com.devsuperior.dslearnbds.repositories.UserRepository;
import com.devsuperior.dslearnbds.services.exceptions.ForbiddenException;
import com.devsuperior.dslearnbds.services.exceptions.UnauthorizedException;

@Service
public class AuthService {

	@Autowired
	private UserRepository userRepository;

	// obtem o nome do usuario que ja foi reconhecido pelo spring security(no caso o email)
	@Transactional(readOnly = true) //Lembrando que o transactional serve para que esta operação nao faça o lock no banco de dados
	public User authenticated() {
		try {
			String username = SecurityContextHolder.getContext().getAuthentication().getName();
			return userRepository.findByEmail(username);
		}catch(Exception e) {
			throw new UnauthorizedException("Invalid user");
		}
	}
	
	public void validateSelfOfAdmin(Long userId) {
		User user = authenticated();
		if(!user.getId().equals(userId) && !user.hasHole("ROLE_ADMIN")) {
			throw new ForbiddenException("Access denied");
		}
	}

}
