package com.geekcatalog.api.domain.profilePic;


import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.GenericGenerator;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;
import com.geekcatalog.api.domain.user.User;

import java.util.UUID;

@Table(name = "profile_pic")
@Entity(name = "ProfilePic")
@Getter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(of = "id")
public class ProfilePic {
    @Id
    @GeneratedValue(generator = "uuid2")
    @GenericGenerator(name = "uuid2", strategy = "org.hibernate.id.UUIDGenerator")
    @Column(name = "id")
    private UUID id;

    @Column(name = "image", columnDefinition = "bytea")
    private byte[] image;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", referencedColumnName = "id")
    @OnDelete(action = OnDeleteAction.CASCADE)
    private User user;

    public ProfilePic(byte[] imageFile, User user) {
        this.image = imageFile;
        this.user = user;
    }

    public void updateImage(byte[] imageFile) {
        this.image = imageFile;
    }

}
