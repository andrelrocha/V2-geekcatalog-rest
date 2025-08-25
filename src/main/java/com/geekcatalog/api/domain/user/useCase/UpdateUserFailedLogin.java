package com.geekcatalog.api.domain.user.useCase;

import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import com.geekcatalog.api.domain.user.User;
import com.geekcatalog.api.domain.user.UserRepository;
import com.geekcatalog.api.infra.exceptions.ValidationException;

import java.time.ZoneId;
import java.time.LocalDateTime;

@Component
@RequiredArgsConstructor
public class UpdateUserFailedLogin {
    private static final int MAX_ATTEMPTS = 5;

    private final UserRepository userRepository;
    private final TaskScheduler taskScheduler;

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void updateFailedLogin(String login) {
        User user = userRepository.findByEmailToHandle(login);

        if (user == null) {
            user = userRepository.findByUsernameToHandle(login);
            if (user == null) {
                throw new ValidationException("No user was found for the provided login: " + login);
            }
        }

        int failedAttempts = user.getAccessFailedCount() + 1;

        if (failedAttempts >= MAX_ATTEMPTS) {
            var lockoutEndTime = LocalDateTime.now().plusMinutes(15);
            user.setLockoutEnabled(true);
            user.setLockoutEnd(lockoutEndTime);
            final User lockedUser = user;
            taskScheduler.schedule(() -> unlockUserAccount(lockedUser),
                    lockoutEndTime.atZone(ZoneId.systemDefault()).toInstant());
        } else {
            user.setAccessFailedCount(failedAttempts);
        }

        userRepository.save(user);
    }

    private void unlockUserAccount(User user) {
        user.setLockoutEnabled(false);
        user.setAccessFailedCount(0);
        user.setLockoutEnd(null);
        userRepository.save(user);
    }
}